"""Network detector: flows in, Findings out.

    flows (flows.py) ──► behaviour rules (rules.py): scans, floods, password guessing, risky ports
                     ├─► names (dns.py): phishing look-ups, DGA names, DNS tunnels
                     ├─► per-device normal (baseline.py): sudden change in behaviour
                     └─► beacons (rules.py), only for servers outside the device's normal

One problem is reported once per 10 minutes (per kind, device and other side), so an
attack that lasts an hour gives a handful of alerts, not thousands.
"""
import ipaddress
import os
import time

from advisor.findings import Finding, verdict_from_score

from .baseline import Baselines
from .dns import NameChecks, load_dga_model
from .flows import FlowRec
from .rules import Beacon, default_rules

LEASES = "/var/lib/NetworkManager/dnsmasq-wlan0.leases"


def defang(text):
    """Make a name or address safe to show: it cannot be clicked."""
    return str(text).replace(".", "[.]") if text else text


def _is_ip(text):
    try:
        ipaddress.ip_address(str(text))
        return True
    except ValueError:
        return False


class NetEngine:
    cooldown_ms = 10 * 60_000

    def __init__(self, url_detector="auto", dga_model="auto", gateway=None, learn_ms=2 * 3600_000,
                 state_path=None, leases=LEASES, beacons=True):
        if url_detector == "auto":
            from detectors.url.detector import UrlDetector
            url_detector = UrlDetector()
        if dga_model == "auto":
            dga_model = load_dga_model()
        self.url = url_detector
        self.rules = default_rules()
        self.beacon = Beacon() if beacons else None
        self.names = NameChecks(url_detector, dga_model)
        self.base = Baselines(learn_ms=learn_ms, gateway=gateway, path=state_path)
        self.gateway = gateway
        self.recent = {}
        self.leases, self.lease_names, self.lease_read = leases, {}, 0.0
        self.flows = 0

    # --- device names from the Pi's DHCP server (shown in the app, never sent to Llama) ---
    def device_name(self, ip):
        if self.leases and time.time() - self.lease_read > 60:
            self.lease_read = time.time()
            names = {}
            try:
                with open(self.leases, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "*":
                            names[parts[2]] = parts[3][:40]
            except OSError:
                pass
            self.lease_names = names
        return self.lease_names.get(ip, "")

    def _peer_name(self, r: FlowRec):
        """The server's registered domain when the flow names it (TLS or HTTP), else None."""
        if r.server_name and not r.is_dns:
            from detectors.url.links import parse_link
            link = parse_link("http://" + r.server_name)
            if link is not None and link.registered:
                return link.registered
        return None

    def feed(self, r: FlowRec):
        """One flow -> new Findings (usually none)."""
        self.flows += 1
        hits = []
        for rule in self.rules:
            hits += rule.update(r)
        hits += self.names.update(r)
        peer = self._peer_name(r)
        hits += self.base.update(r, peer)
        if self.beacon is not None:
            for h in self.beacon.update(r, peer or ""):
                known = self.base.knows(r.src, peer or r.dst) or (peer and peer in self.names.top)
                if not known and not self.base.learning(r.src, r.start_ms):
                    hits.append(h)
        out = []
        for h in hits:
            key = (h.category, h.device, h.peer)
            last = self.recent.get(key)              # (time, score) of the last alert like this one
            if last is not None and r.start_ms - last[0] < self.cooldown_ms and h.score <= last[1] + 0.1:
                continue                             # already reported, and not worse now
            self.recent[key] = (r.start_ms, h.score)
            if len(self.recent) > 50_000:
                self.recent = {k: v for k, v in self.recent.items() if r.start_ms - v[0] < self.cooldown_ms}
            out.append(self._finding(h, r))
        return out

    def _finding(self, h, r):
        entities = {"device": h.device, "peer": h.peer if _is_ip(h.peer) else defang(h.peer),
                    "time_ms": r.start_ms}
        name = self.device_name(h.device)
        if name:
            entities["device_name"] = name            # chosen by the device itself: shown, never sent to Llama
        for k, v in h.facts.items():
            if k in ("name", "examples"):
                v = [defang(x) for x in v] if isinstance(v, list) else defang(v)
            entities[k] = v
        if r.label:
            entities["label"] = r.label               # test data only
        return Finding(source="net", verdict=verdict_from_score(h.score), score=round(h.score, 3),
                       category=h.category, reasons=list(h.reasons), entities=entities)

    def save(self):
        self.base.save()

    def info(self):
        return {"flows": self.flows, "devices": len(self.base.devices), "dga_model": self.names.dga is not None,
                "link_checker": self.url is not None}


def default_state_path(root=None):
    root = root or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "data", "net", "devices.json")

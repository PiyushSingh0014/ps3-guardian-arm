"""Behaviour rules over a stream of flows: scans, floods, password guessing, beacons.

Each rule keeps a little state per device and looks back over a short time window. The
thresholds below are prior assumptions from how these attacks work (and from tools'
defaults), not values fitted to a test set; eval_net.py measures them on CIC-IDS2017.

Every hit says what happened in plain words. Reasons may contain IP addresses and
numbers, never a device's self-chosen name: they are passed to Llama later.
"""
from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import mean, median, pstdev

from .flows import TCP, UDP, FlowRec, is_private

# Ports where a login is checked: many quick tries there means password guessing.
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "e-mail (SMTP)", 110: "e-mail (POP3)", 143: "e-mail (IMAP)",
              445: "Windows file sharing (SMB)", 465: "e-mail (SMTP)", 587: "e-mail (SMTP)", 993: "e-mail (IMAP)",
              995: "e-mail (POP3)", 1433: "a database (SQL Server)", 2323: "Telnet", 3306: "a database (MySQL)",
              3389: "Windows remote desktop", 5432: "a database (PostgreSQL)", 5900: "remote screen (VNC)"}
# Outgoing connections on these ports from a home device are a sign of malware.
RISKY_PORTS = {23: "Telnet", 2323: "Telnet", 6667: "IRC chat, used to control bots",
               6697: "IRC chat, used to control bots", 4444: "a port used by hacking tools", 9001: "Tor", 9030: "Tor", 445: "Windows file sharing (SMB)",
               139: "Windows file sharing (NetBIOS)", 135: "Windows RPC"}


@dataclass
class Hit:
    category: str             # playbook key
    device: str               # the address the alert is about (usually the one doing it)
    peer: str                 # the other side (address, or a name for DNS alerts)
    score: float              # 0..1, like other detectors
    reasons: list
    facts: dict = field(default_factory=dict)   # numbers for the app and the log


class _Recent:
    """Things seen per key within the last `window_ms` (key -> {item: last time})."""

    def __init__(self, window_ms):
        self.window = window_ms
        self.items = defaultdict(dict)
        self.seen = 0

    def add(self, key, item, t):
        d = self.items[key]
        d[item] = t
        self.seen += 1
        if len(d) > 64 and self.seen % 64 == 0:
            self._prune(d, t)
        if self.seen % 50000 == 0:
            self.gc(t)
        return d

    def count(self, key, t):
        d = self.items.get(key)
        if not d:
            return 0
        self._prune(d, t)
        return len(d)

    def _prune(self, d, t):
        old = [k for k, v in d.items() if t - v > self.window]
        for k in old:
            del d[k]

    def gc(self, t):
        for key in [k for k, d in self.items.items() if not d or t - max(d.values()) > self.window]:
            del self.items[key]


class _Times:
    """Event times per key within the last `window_ms`."""

    def __init__(self, window_ms):
        self.window = window_ms
        self.times = defaultdict(deque)
        self.seen = 0

    def add(self, key, t):
        q = self.times[key]
        q.append(t)
        while q and t - q[0] > self.window:
            q.popleft()
        self.seen += 1
        if self.seen % 50000 == 0:
            for k in [k for k, v in self.times.items() if not v or t - v[-1] > self.window]:
                del self.times[k]
        return len(q)


def _sec(ms):
    s = max(1, round(ms / 1000))
    return f"{s} seconds" if s < 120 else f"{round(s / 60)} minutes"


class PortScan:
    """One address trying many ports on another: someone looking for a way in."""
    window_ms, at, high = 60_000, 20, 100

    def __init__(self):
        self.ports = _Recent(self.window_ms)

    def update(self, r: FlowRec):
        if r.proto not in (TCP, UDP) or not r.failed or r.looks_like_reply:
            return []
        key = (r.src, r.dst)
        d = self.ports.add(key, r.dport, r.start_ms)
        n = len(d)
        if n < self.at:
            return []
        n = self.ports.count(key, r.start_ms)
        if n < self.at:
            return []
        span = r.start_ms - min(d.values())
        score = 0.95 if n >= self.high else 0.75
        return [Hit("port_scan", r.src, r.dst, score,
                    [f"{r.src} tried {n} different ports on {r.dst} within {_sec(max(span, 1000))}, "
                     "most of them closed: that is how attackers look for a way in"],
                    {"ports": n, "window_s": round(span / 1000)})]


class HostSweep:
    """One address trying the same port on many machines that never answer: a worm or bot
    spreading. Machines that answered once in the window do not count, so a browser that
    opens many connections to working websites is not a sweep."""
    window_ms, at, high = 60_000, 15, 50

    def __init__(self):
        self.hosts = _Recent(self.window_ms)
        self.answered = _Recent(self.window_ms)

    def update(self, r: FlowRec):
        if r.proto not in (TCP, UDP) or r.looks_like_reply or r.dport in (53, 123, 5353, 1900, 137, 138):
            return []
        key = (r.src, r.dport)
        if not r.failed:
            self.answered.add(key, r.dst, r.start_ms)
            self.hosts.items.get(key, {}).pop(r.dst, None)
            return []
        if r.dst in self.answered.items.get(key, {}):
            return []
        d = self.hosts.add(key, r.dst, r.start_ms)
        if len(d) < self.at or self.hosts.count(key, r.start_ms) < self.at:
            return []
        n = len(d)
        telnet = r.dport in (23, 2323)
        score = 0.95 if (n >= self.high or telnet) else 0.75
        what = RISKY_PORTS.get(r.dport) or AUTH_PORTS.get(r.dport) or f"port {r.dport}"
        why = [f"{r.src} tried to connect to {n} different machines on {what} within a minute, mostly without answer"]
        if telnet:
            why.append("scanning for Telnet is what Mirai-type botnets do from infected cameras and routers")
        return [Hit("network_scan", r.src, f"port {r.dport}", score, why, {"hosts": n, "port": r.dport})]


class Flood:
    """A flood of connections from one address to one target: denial of service."""
    window_ms, at, syn_at = 10_000, 300, 200

    def __init__(self):
        self.flows = _Times(self.window_ms)
        self.syns = _Times(self.window_ms)

    def update(self, r: FlowRec):
        if r.dport in (53, 123, 137, 138, 5353) or r.looks_like_reply:     # name lookups and time sync
            return []
        key = (r.src, r.dst, r.dport)
        n = self.flows.add(key, r.start_ms)
        syn_only = r.proto == TCP and r.syn_out > 0 and r.bytes_out == 0 and r.pkts_out <= 2
        s = self.syns.add(key, r.start_ms) if syn_only else 0
        if n >= self.at or s >= self.syn_at:
            what = (f"{s} half-open connection requests (SYN flood)" if s >= self.syn_at
                    else f"{n} connections")
            return [Hit("dos_flood", r.src, r.dst, 0.95,
                        [f"{r.src} sent {what} to {r.dst} port {r.dport} within 10 seconds: "
                         "a flood meant to overload it"], {"flows_10s": n, "syn_10s": s, "port": r.dport})]
        return []


class SlowDos:
    """Many long, almost silent connections to one web server: slowloris-type attacks."""
    window_ms, at = 60_000, 50

    def __init__(self):
        self.slow = _Times(self.window_ms)

    def update(self, r: FlowRec):
        if r.proto != TCP or r.duration_ms < 20_000 or r.bytes_out > 2000:
            return []
        n = self.slow.add((r.src, r.dst, r.dport), r.start_ms)
        if n < self.at:
            return []
        return [Hit("dos_flood", r.src, r.dst, 0.85,
                    [f"{r.src} kept {n} slow, nearly empty connections open to {r.dst} port {r.dport}: "
                     "a way to tie up a server"], {"slow_flows": n, "port": r.dport})]


class BruteForce:
    """Many short tries at a login port: password guessing."""
    window_ms, at, high = 60_000, 15, 40

    def __init__(self):
        self.tries = _Times(self.window_ms)

    def update(self, r: FlowRec):
        if r.proto != TCP or r.dport not in AUTH_PORTS or r.duration_ms > 15_000 or r.bytes_out > 10_000:
            return []
        n = self.tries.add((r.src, r.dst, r.dport), r.start_ms)
        if n < self.at:
            return []
        return [Hit("brute_force", r.src, r.dst, 0.95 if n >= self.high else 0.8,
                    [f"{r.src} made {n} short login attempts on {AUTH_PORTS[r.dport]} at {r.dst} within a minute: "
                     "someone is guessing passwords"], {"tries_60s": n, "port": r.dport})]


class RiskyPort:
    """A home device connecting out on a port used to spread or control malware."""

    def update(self, r: FlowRec):
        if r.dport not in RISKY_PORTS or not is_private(r.src) or is_private(r.dst) or r.proto != TCP:
            return []
        return [Hit("risky_port", r.src, f"port {r.dport}", 0.6,
                    [f"{r.src} connected to an internet address on {RISKY_PORTS[r.dport]} (port {r.dport}), "
                     "which home devices normally never use"], {"port": r.dport, "first_server": r.dst})]


class Beacon:
    """A device contacting the same server at a fixed rhythm: malware checking in.

    Many apps also call home regularly (updates, cloud sensors), so a beacon alone is only
    suspicious, and only for servers outside the most visited websites and the device's
    own normal list (baseline.py tells the engine which are normal).
    """
    min_events, max_cv, min_interval_ms = 10, 0.15, 30_000

    def __init__(self):
        self.starts = defaultdict(lambda: deque(maxlen=16))
        self.seen = 0

    def update(self, r: FlowRec, peer_name=""):
        if not is_private(r.src) or is_private(r.dst) or r.dport in (53, 123, 5353) or r.proto not in (TCP, UDP):
            return []
        key = (r.src, peer_name or r.dst, r.dport)
        self.seen += 1
        if self.seen % 50000 == 0:              # forget servers not contacted for an hour
            for k in [k for k, q in self.starts.items() if r.start_ms - q[-1] > 3_600_000]:
                del self.starts[k]
        q = self.starts[key]
        if q and r.start_ms - q[-1] < 1000:          # parts of one burst, not a new check-in
            return []
        q.append(r.start_ms)
        if len(q) < self.min_events:
            return []
        gaps = [b - a for a, b in zip(q, list(q)[1:])]
        m = mean(gaps)
        if m < self.min_interval_ms or pstdev(gaps) / m > self.max_cv:
            return []
        every = median(gaps)
        return [Hit("malware_beacon", r.src, peer_name or r.dst, 0.6,
                    [f"{r.src} contacts {peer_name or r.dst} every {_sec(every)}, like clockwork "
                     f"({len(q)} times so far): malware checks in with its controller this way"],
                    {"interval_s": round(every / 1000), "times": len(q), "port": r.dport})]


def default_rules():
    return [PortScan(), HostSweep(), Flood(), SlowDos(), BruteForce(), RiskyPort()]

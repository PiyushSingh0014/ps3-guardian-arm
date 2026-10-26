"""Checks on the names devices look up (DNS) and the servers they connect to by name.

  * a known phishing site, or a brand's name on someone else's site: the link checker
    (detectors/url) judges the name, and only its decisive findings count here;
  * many random-looking names in a short time: malware searching for its controller
    with a domain generation algorithm (DGA, dga_model.npz from train_dga.py);
  * many long, unique sub-names under one website: data smuggled out through DNS.

Names are chosen by whoever registered them, so they stay out of the reasons (which go
to Llama) and appear only, made unclickable, in the alert's details.
"""
import os

from detectors.url.links import parse_link

from .flows import FlowRec
from .rules import Hit, _Recent

HERE = os.path.dirname(os.path.abspath(__file__))
DGA_MODEL = os.path.join(HERE, "dga_model.npz")


class NameChecks:
    dga_at = 0.9                     # model score for "looks machine-made"
    dga_window_ms, dga_names = 10 * 60_000, 5
    tunnel_window_ms, tunnel_names, tunnel_len = 10 * 60_000, 25, 18
    cache_max = 20_000

    def __init__(self, url_detector=None, dga_model=None, top_sites=None):
        self.url = url_detector
        self.dga = dga_model
        self.top = set(top_sites or ()) | (set(url_detector.top_sites) if url_detector is not None else set())
        self.dga_seen = _Recent(self.dga_window_ms)
        self.subs = _Recent(self.tunnel_window_ms)
        self.cache = {}

    def _judge(self, name):
        """(link, link verdict or None, DGA score or None) for a name, cached."""
        hit = self.cache.get(name)
        if hit is not None:
            return hit
        link = parse_link("http://" + name)
        verdict = dga = None
        if link is not None and not link.is_ip:
            if self.url is not None:
                verdict = self.url.check_link(link)
            if self.dga is not None and link.registered not in self.top and len(link.domain) >= 6 \
                    and not (verdict is not None and verdict.official):
                dga = self.dga.score(link.domain, "")
        if len(self.cache) >= self.cache_max:
            self.cache.clear()
        self.cache[name] = (link, verdict, dga)
        return self.cache[name]

    def update(self, r: FlowRec):
        name = r.server_name
        if not name or " " in name:
            return []
        link, verdict, dga = self._judge(name)
        if link is None:
            return []
        hits = []
        if verdict is not None and (verdict.decisive or verdict.listed):
            why = (f"{r.src} looked up a website that is on the public list of phishing sites" if verdict.listed
                   else f"{r.src} looked up a fake website: {verdict.reasons[0]}" if verdict.reasons
                   else f"{r.src} looked up a dangerous website")
            hits.append(Hit("phishing_lookup", r.src, link.registered, 0.95 if verdict.listed else 0.9, [why],
                            {"name": name, "brand": verdict.brand} if verdict.brand else {"name": name}))
        if not r.is_dns:
            return hits
        if dga is not None and dga >= self.dga_at:
            d = self.dga_seen.add(r.src, link.registered, r.start_ms)
            if len(d) >= self.dga_names and self.dga_seen.count(r.src, r.start_ms) >= self.dga_names:
                n = len(d)
                hits.append(Hit("dga_domains", r.src, "random names", 0.95 if n >= 2 * self.dga_names else 0.85,
                                [f"{r.src} looked up {n} different random-looking website names within 10 minutes: "
                                 "malware makes up names like these to find its controller"],
                                {"names": n, "examples": sorted(d)[:3]}))
        if link.subdomain and len(link.subdomain) >= self.tunnel_len:
            key = (r.src, link.registered)
            d = self.subs.add(key, link.subdomain, r.start_ms)
            if len(d) >= self.tunnel_names and self.subs.count(key, r.start_ms) >= self.tunnel_names:
                avg = sum(len(s) for s in d) / len(d)
                hits.append(Hit("dns_tunnel", r.src, link.registered, 0.9,
                                [f"{r.src} made {len(d)} long, never-repeating DNS lookups under one website "
                                 f"(about {avg:.0f} characters each) within 10 minutes: a way to smuggle data "
                                 "out, or to control malware, through DNS"],
                                {"names": len(d), "avg_len": round(avg)}))
        return hits


def load_dga_model(path=DGA_MODEL):
    if not path or not os.path.exists(path):
        return None
    from detectors.url.model import LinkModel
    try:
        return LinkModel.load(path)
    except (ValueError, KeyError, OSError) as e:
        print(f"[net] could not load {path} ({e}); DGA check off")
        return None


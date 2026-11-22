"""What is normal for each device, learned from its own traffic.

An ESP32 sensor talks to the same one or two servers all day; a hacked one suddenly
talks to dozens and sends much more. For every device on the Pi's network this keeps,
per 5 minutes: connections, data sent and received, distinct servers, distinct ports and
DNS lookups, plus the set of servers it normally uses. The first two hours of a device
are learning only; after that a 5-minute period far above the device's own usual (3x its
99th percentile, and above a floor) that also brings many new servers is reported.

This is for small home devices. A device that used more than GENERAL_PEERS servers while
learning is a laptop or phone: how much it does follows its user, so "unlike its normal self"
is no sign of trouble there and is not reported (lab Wi-Fi, 5 November 2026: a laptop opening
30 websites in 10 minutes). The other checks still watch it.

Nothing about the content of the traffic is kept: only these counts and the addresses or
names of the servers a device uses (data/net/devices.json on the Pi).
"""
import json
import os
from dataclasses import dataclass, field

from .flows import FlowRec, is_device
from .rules import Hit

BUCKET_MS = 5 * 60_000
METRICS = ("flows", "bytes_out", "bytes_in", "servers", "ports", "dns")
TRIGGERS = ("flows", "bytes_out", "servers", "ports", "dns")      # a big download alone is not a threat
FLOORS = {"flows": 60, "bytes_out": 2_000_000, "bytes_in": 20_000_000, "servers": 20, "ports": 20, "dns": 60}
WORDS = {"flows": "connections", "bytes_out": "data sent", "bytes_in": "data received",
         "servers": "different servers", "ports": "different ports", "dns": "DNS lookups"}
MAX_PEERS, MAX_HISTORY = 5000, 2016           # a week of 5-minute periods
GENERAL_PEERS = 50                             # more servers while learning: a laptop or phone


def _p99(values):
    v = sorted(values)
    return v[min(len(v) - 1, int(0.99 * (len(v) - 1) + 0.5))] if v else 0


def _amount(metric, x):
    if metric.startswith("bytes"):
        return f"{x / 1e6:.1f} MB" if x >= 1e6 else f"{x / 1e3:.0f} KB"
    return f"{int(x)}"


@dataclass
class Device:
    first_ms: int
    last_ms: int = 0                                   # its latest connection (for the app's device list)
    peers: set = field(default_factory=set)            # servers used while learning: its normal
    later: set = field(default_factory=set)            # servers first used after learning (reported once)
    history: list = field(default_factory=list)        # one dict of METRICS per 5 minutes
    start: int = 0
    cur: dict = field(default_factory=dict)
    cur_servers: set = field(default_factory=set)
    cur_ports: set = field(default_factory=set)
    new_peers: set = field(default_factory=set)

    def reset(self, start):
        self.start = start
        self.cur = {m: 0 for m in METRICS}
        self.cur_servers, self.cur_ports, self.new_peers = set(), set(), set()


class Baselines:
    min_new_peers = 5

    def __init__(self, learn_ms=2 * 3600_000, gateway=None, path=None):
        self.learn_ms = learn_ms
        self.gateway = gateway
        self.path = path
        self.devices = {}
        if path and os.path.exists(path):
            self.load(path)

    def learning(self, device, t):
        d = self.devices.get(device)
        return d is None or t - d.first_ms < self.learn_ms

    def knows(self, device, peer):
        d = self.devices.get(device)
        return d is not None and peer in d.peers

    def update(self, r: FlowRec, peer=None):
        if not is_device(r.src) or r.src == self.gateway:
            return []
        d = self.devices.get(r.src)
        if d is None:
            d = self.devices[r.src] = Device(first_ms=r.start_ms)
            d.reset(r.start_ms - r.start_ms % BUCKET_MS)
        hits = []
        if r.start_ms >= d.start + BUCKET_MS:
            hits = self._close(r.src, d, r.start_ms)
        peer = peer or r.dst
        d.last_ms = max(d.last_ms, r.start_ms)
        c = d.cur
        c["flows"] += 1
        c["bytes_out"] += r.bytes_out
        c["bytes_in"] += r.bytes_in
        c["dns"] += int(r.is_dns)
        d.cur_servers.add(peer)
        d.cur_ports.add(r.dport)
        if peer not in d.peers:
            if r.start_ms - d.first_ms < self.learn_ms:
                if len(d.peers) < MAX_PEERS:
                    d.peers.add(peer)
            elif peer not in d.later:
                d.new_peers.add(peer)
        return hits

    def _close(self, device, d, t):
        c = d.cur
        c["servers"], c["ports"] = len(d.cur_servers), len(d.cur_ports)
        hits = []
        learned = d.start - d.first_ms >= self.learn_ms and len(d.history) >= 6
        if learned and c["flows"] and len(d.peers) <= GENERAL_PEERS:
            over = []
            for m in TRIGGERS:
                limit = max(3 * _p99(h[m] for h in d.history), FLOORS[m])
                if c[m] > limit:
                    usual = _p99(h[m] for h in d.history)
                    over.append(f"{_amount(m, c[m])} {WORDS[m]} in 5 minutes (its usual most is {_amount(m, usual)})")
            if over and len(d.new_peers) >= self.min_new_peers:
                hits.append(Hit("device_anomaly", device, f"{len(d.new_peers)} new servers", 0.7,
                                [f"{device} is behaving unlike its normal self: " + "; ".join(over[:2]),
                                 f"{device} talked to {len(d.new_peers)} servers it never used before"],
                                {"new_servers": len(d.new_peers), **{m: c[m] for m in METRICS}}))
        if c["flows"]:
            d.history.append(dict(c))
            del d.history[:-MAX_HISTORY]
        for p in d.new_peers:                      # counted once; still not "normal" for the beacon check
            if len(d.later) < MAX_PEERS:
                d.later.add(p)
        d.reset(t - t % BUCKET_MS)
        return hits

    # --- keep what was learned across restarts --------------------------
    def save(self, path=None):
        path = path or self.path
        if not path:
            return
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = {ip: {"first_ms": d.first_ms, "last_ms": d.last_ms, "peers": sorted(d.peers)[:MAX_PEERS],
                     "later": sorted(d.later)[:MAX_PEERS], "history": d.history[-MAX_HISTORY:]}
                for ip, d in self.devices.items()}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def load(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        for ip, v in data.items():
            d = Device(first_ms=int(v.get("first_ms", 0)), last_ms=int(v.get("last_ms", 0)),
                       peers=set(v.get("peers", [])), later=set(v.get("later", [])),
                       history=list(v.get("history", [])))
            d.reset(0)
            self.devices[ip] = d

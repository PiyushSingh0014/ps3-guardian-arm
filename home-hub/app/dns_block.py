"""Websites the Pi refuses to look up for the devices on its Wi-Fi: DNS blocking (update 40).

The Pi is the DNS server of its hotspot: NetworkManager runs dnsmasq for it. The app and the network
monitor write the names to block into data/net/blocklist.json. A root helper, started by systemd
whenever that file changes (scripts/setup_dns_block.sh installs it), turns the list into dnsmasq
"server=/name/" lines and makes dnsmasq read them again. dnsmasq then answers NXDOMAIN for the name
and every name under it, so the page does not open on any device on the Wi-Fi.

Blocked automatically, for 7 days:
  * the websites of a message the Pi judged dangerous (they also go on the watch list);
  * a website a device looked up that is on the public phishing list, or that puts a brand's name
    on someone else's site (the monitor's decisive phishing look-ups);
  * a website from a flagged message that a device then opened ("Link from a scam message opened").
Blocked by hand on the page, until unblocked. Undo: Unblock on the page. A website unblocked there
is remembered as allowed and not blocked automatically again (a hand block still works).
Never blocked: official sites, popular sites, link shorteners, chat links, shared services and IP
addresses, the watch list's exceptions: blocking one of them would cut off everyone.

    python -m app.dns_block list
    python -m app.dns_block block example.org          # by hand, as on the page (inside the venv)
    python -m app.dns_block unblock example.org
    python -m app.dns_block check example.org          # what the Pi's DNS answers now
    python -m app.dns_block selftest                    # block example.org for a moment and look

Standard library only, except `block`, which needs the link checker (the venv) to refuse official and
popular websites as the page does: scripts/setup_dns_block.sh runs the self-test with the system Python.
"""
import argparse
import contextlib
import fcntl
import json
import os
import random
import re
import socket
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIST = os.path.join(ROOT, "data", "net", "blocklist.json")
SERVERS = "/var/lib/ps3-guardian/blocked.servers"            # written by the root helper
CONF = "/etc/NetworkManager/dnsmasq-shared.d/ps3-block.conf"  # written by setup_dns_block.sh
PI_DNS = "10.42.0.1"
AUTO_DAYS = 7
MAX_NAMES = 1000
AUTO_SOURCES = ("message", "network")
SOURCES = AUTO_SOURCES + ("page", "test")
SKIP_KINDS = {"official", "popular", "shortener", "chat", "shared", "ip"}     # as the watch list
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
NAME_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")


def valid_name(name):
    """The name in the form dnsmasq is given (lower case, no final dot, IDNA), or None."""
    n = str(name or "").strip().lower().rstrip(".")
    for prefix in ("http://", "https://"):
        if n.startswith(prefix):
            n = n[len(prefix):]
    n = n.split("/")[0].split(":")[0]
    try:
        n = n.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return n if len(n) <= 253 and NAME_RE.match(n) else None


def protected_reason(url_detector, name):
    """Why blocking this name would cut off everyone (official, popular, shared...), or None."""
    if url_detector is None:
        return None
    from detectors.url.links import parse_link
    link = parse_link("http://" + name)
    if link is None:
        return "not a website name"
    kind = url_detector.check_link(link).kind
    if kind in SKIP_KINDS:
        return {"official": "an official website", "popular": "one of the most visited websites",
                "shortener": "a link shortener many genuine messages use", "chat": "a chat service",
                "shared": "a shared service (files, forms, hosting) everyone uses",
                "ip": "an address, not a website name"}[kind]
    return None


class BlockList:
    """The block list in data/net/blocklist.json, shared by the app and the network monitor."""

    def __init__(self, path=None, clock=time.time, protected=None):
        self.path = str(path or os.environ.get("GUARDIAN_BLOCKLIST", LIST))
        self.clock, self.protected = clock, protected

    @contextlib.contextmanager
    def _locked(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        now = self.clock() * 1000
        blocked = {k: v for k, v in (data.get("blocked") or {}).items()
                   if isinstance(v, dict) and (v.get("until_ms") is None or v["until_ms"] > now)}
        allowed = {k: v for k, v in (data.get("allowed") or {}).items() if isinstance(v, dict)}
        return {"version": 1, "blocked": blocked, "allowed": allowed}

    def _save(self, data):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.path)          # systemd sees the change and the root helper applies it

    def entries(self):
        """[(name, entry)] newest first."""
        data = self._load()
        return sorted(data["blocked"].items(), key=lambda kv: -kv[1].get("since_ms", 0))

    def is_blocked(self, name):
        """The entry blocking this name (itself or a name it is under), or None."""
        n = valid_name(name)
        if not n:
            return None
        blocked = self._load()["blocked"]
        parts = n.split(".")
        for i in range(len(parts) - 1):
            e = blocked.get(".".join(parts[i:]))
            if e:
                return e
        return None

    def block(self, names, why, source, days=AUTO_DAYS):
        """Block these names. Returns (added, refused: {name: reason}). Automatic sources skip names
        unblocked by hand; days=None blocks until unblocked."""
        if source not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}")
        now = int(self.clock() * 1000)
        added, refused, todo = [], {}, []
        for raw in names:
            n = valid_name(raw)
            if not n:
                refused[str(raw)] = "not a website name"
                continue
            reason = self.protected(n) if self.protected else None
            if reason:
                refused[n] = f"{n} is {reason}: blocking it would cut off everyone"
                continue
            todo.append(n)
        if not todo:
            return added, refused
        with self._locked():
            data = self._load()
            for n in todo:
                if source in AUTO_SOURCES and n in data["allowed"]:
                    refused[n] = f"{n} was unblocked by hand, so it is not blocked automatically again"
                    continue
                old = data["blocked"].get(n)
                if old and (old.get("until_ms") is None or (days is not None and old["until_ms"] >= now + days * 86_400_000)):
                    continue                                     # already blocked at least as long
                if source == "page":
                    data["allowed"].pop(n, None)
                data["blocked"][n] = {"since_ms": old.get("since_ms", now) if old else now,
                                      "until_ms": None if days is None else now + int(days * 86_400_000),
                                      "why": str(why)[:200], "source": source}
                added.append(n)
            if len(data["blocked"]) > MAX_NAMES:                 # drop the oldest automatic ones
                auto = sorted((v.get("since_ms", 0), k) for k, v in data["blocked"].items()
                              if v.get("source") in AUTO_SOURCES)
                for _, k in auto[:len(data["blocked"]) - MAX_NAMES]:
                    del data["blocked"][k]
            if added:
                self._save(data)
        return added, refused

    def unblock(self, name, remember=True):
        """True if it was blocked. remember: not blocked automatically again (the page's Unblock)."""
        n = valid_name(name)
        if not n:
            return False
        with self._locked():
            data = self._load()
            was = data["blocked"].pop(n, None)
            if remember:
                data["allowed"][n] = {"since_ms": int(self.clock() * 1000)}
            if was is not None or remember:
                self._save(data)
        return was is not None

    def status(self, servers=SERVERS, conf=CONF):
        """Is blocking set up on this Pi, and has the newest list been applied?"""
        entries = self.entries()
        on = os.path.exists(conf) and os.path.exists(servers)
        applied = None
        if on:
            try:
                applied = os.path.getmtime(servers) >= os.path.getmtime(self.path) - 1
            except OSError:
                applied = not entries
        return {"set_up": on, "applied": applied, "names": len(entries),
                "note": None if on else "DNS blocking is not set up on this Pi: bash scripts/setup_dns_block.sh"}

    def listing(self):
        def item(name, e):
            return {"name": name, "why": e.get("why", ""), "source": e.get("source", ""),
                    "since": time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("since_ms", 0) / 1000)),
                    "until": None if e.get("until_ms") is None else
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(e["until_ms"] / 1000))}
        return {**self.status(), "blocked": [item(n, e) for n, e in self.entries()]}


# --- what the Pi's DNS answers ------------------------------------------------------------
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _skip_name(data, i):
    while i < len(data):
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:                       # a pointer ends the name
            return i + 2
        i += 1 + n
    raise ValueError("cut-off name")


def query(name, server=PI_DNS, port=53, timeout=2.0):
    """(answer code, [IPv4 addresses]) for an A look-up of `name` at the Pi's DNS server."""
    tid = random.getrandbits(16)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            data = s.recv(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
            if time.monotonic() > deadline:
                raise socket.timeout("no answer")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    i = 12
    for _ in range(qd):
        i = _skip_name(data, i) + 4
    addresses = []
    for _ in range(an):
        i = _skip_name(data, i)
        rtype, _, _, rlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rlen == 4:
            addresses.append(socket.inet_ntoa(data[i:i + 4]))
        i += rlen
    return RCODES.get(flags & 0xF, str(flags & 0xF)), addresses


def answer(name, server=PI_DNS):
    try:
        code, addresses = query(name, server)
    except OSError as e:
        return f"no answer from the Pi's DNS at {server} ({e})"
    if code == "NXDOMAIN":
        return "NXDOMAIN: no such website (blocked, or it does not exist)"
    return f"{code}" + (f": {', '.join(addresses)}" if addresses else "")


def wait_for(name, want, server=PI_DNS, seconds=20.0):
    """The answer code once it is `want` (a code or a set of codes), or the last one seen."""
    want = {want} if isinstance(want, str) else set(want)
    code = None
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            code = query(name, server)[0]
        except OSError:
            code = "no answer"
        if code in want:
            return code
        time.sleep(0.5)
    return code


def selftest(blocks=None, name="example.org", server=PI_DNS, say=print):
    """Block `name` for a moment and check that the Pi's DNS refuses it, then that it answers again.
    example.org is IANA's example domain: nothing on the Wi-Fi needs it."""
    blocks = blocks or BlockList()
    if blocks.is_blocked(name):          # blocked by hand (the guide's "Try it"): check it, leave it alone
        code = wait_for(name, "NXDOMAIN", server, 20)
        if code != "NXDOMAIN":
            say(f"FAIL: {name} is on the block list but the Pi's DNS answers {code}. "
                "Look at: systemctl status ps3-dnsblock.service --no-pager")
            return 1
        say(f"{name} is already on the block list and the Pi's DNS refuses it (NXDOMAIN): DNS blocking works. "
            "The block was left in place; unblock it on the page to test unblocking too.")
        return 0
    before = wait_for(name, {"NOERROR", "SERVFAIL"}, server, 30)
    if before not in ("NOERROR", "SERVFAIL"):
        say(f"FAIL: the Pi's DNS at {server} does not answer ({before}).")
        return 1
    say(f"The Pi's DNS answers ({name}: {before}" + ("" if before == "NOERROR" else ", no internet now") + ").")
    blocks.block([name], why="self-test of DNS blocking", source="test", days=1 / 24)
    try:
        during = wait_for(name, "NXDOMAIN", server, 20)
    finally:
        blocks.unblock(name, remember=False)
    if during != "NXDOMAIN":
        say(f"FAIL: {name} was blocked but the Pi's DNS still answers {during}. "
            "Look at: systemctl status ps3-dnsblock.service --no-pager")
        return 1
    say(f"Blocked: the Pi's DNS refused {name} (NXDOMAIN).")
    after = wait_for(name, before, server, 20)
    if after != before:
        say(f"FAIL: {name} was unblocked but the Pi's DNS answers {after}, not {before}.")
        return 1
    say(f"Unblocked: {name} answers again. DNS blocking works.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for cmd in ("block", "unblock", "check"):
        sub.add_parser(cmd).add_argument("name")
    sub.add_parser("selftest")
    for p in sub.choices.values():
        p.add_argument("--list", default=LIST, help=argparse.SUPPRESS)
        p.add_argument("--server", default=PI_DNS, help="the DNS server to ask (default: the Pi's hotspot)")
    a = ap.parse_args(argv)
    blocks = BlockList(a.list)
    if a.cmd == "list":
        d = blocks.listing()
        print(d["note"] or f"DNS blocking is set up; {d['names']} websites blocked"
              + ("" if d["applied"] in (None, True) else " (the newest change is not applied yet)") + ".")
        for e in d["blocked"]:
            print(f"  {e['name']:40s} {e['source']:8s} since {e['since']}"
                  + (f", until {e['until']}" if e["until"] else ", until unblocked") + f"  {e['why']}")
        return 0
    if a.cmd == "block":
        try:                                 # the page's protection: never official, popular or shared sites
            from detectors.url.detector import UrlDetector
            detector = UrlDetector()
        except Exception as e:               # the system Python has no scikit-learn: not in the venv
            print(f"Cannot load the link checker here ({type(e).__name__}), so it cannot tell whether {a.name} "
                  "is an official or popular website. Block it on the Pi's page, or run this inside the venv: "
                  "source ~/ps3-venv/bin/activate")
            return 1
        blocks.protected = lambda n: protected_reason(detector, n)
        added, refused = blocks.block([a.name], why="blocked by hand (command line)", source="page", days=None)
        print(f"Blocked {added[0]}." if added else (next(iter(refused.values()), "Already blocked.")))
        return 0 if added or not refused else 1
    if a.cmd == "unblock":
        ok = blocks.unblock(a.name)
        print(f"Unblocked {a.name}." if ok else f"{a.name} was not blocked; it will not be blocked automatically.")
        return 0
    if a.cmd == "check":
        n = valid_name(a.name)
        if not n:
            print("not a website name")
            return 1
        print(f"{n}: {answer(n, a.server)}" + (" | on the block list" if blocks.is_blocked(n) else ""))
        return 0
    return selftest(blocks, server=a.server)


if __name__ == "__main__":
    sys.exit(main())

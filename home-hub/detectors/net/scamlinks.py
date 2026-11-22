"""Links from scam messages, watched on the lab Wi-Fi: where messages meet network traffic.

When the Pi flags an SMS, a chat or a message pasted on its page, the app (app/server.py)
writes the websites its links point to into data/fusion/watch.json, for 24 hours. The
network monitor reads that file, and when a device on the lab Wi-Fi looks up one of those
websites, it raises "Link from a scam message opened" for that device (rules in dns.py).

This catches scam links that the link checker alone rates safe: short domains such as the
ones real Indian scams use look just like genuine bulk-SMS link domains. The message's
sender and text gave it away; the lookup shows that someone opened it.

Left out: official sites, popular sites, link shorteners, chat links and shared services
(Google Drive and the like). Everyone opens those all day, so a match would say nothing.
Only the website names are kept (no text, no sender), and each for 24 hours.
"""
import json
import os
import time

from detectors.url.links import parse_link

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WATCH = os.path.join(ROOT, "data", "fusion", "watch.json")
KEEP_MS = 24 * 3600_000
MAX_SITES = 500
SKIP_KINDS = {"official", "popular", "shortener", "chat", "shared", "ip"}
RELOAD_S = 5.0


def sites_from(finding):
    """The websites (registered domains) worth watching from a flagged Finding's links."""
    e = finding.entities or {}
    links = list(e.get("links") or [])
    if e.get("link"):                                   # one link checked on its own (POST /url)
        links.append({"link": e["link"], "kind": e.get("link_kind", "")})
    out = []
    for item in links:
        if not isinstance(item, dict) or item.get("kind") in SKIP_KINDS:
            continue
        host = str(item.get("link") or "").replace("[.]", ".")
        link = parse_link("http://" + host) if host else None
        if link is not None and link.registered and link.registered not in out:
            out.append(link.registered)
    return out


def where_from(channel, sender_type):
    """How the message came, in words for the alert: 'an SMS from a mobile number'."""
    if channel == "sms":
        return {"mobile_number": "an SMS from a mobile number",
                "registered_sender_id": "an SMS from a registered sender ID"}.get(sender_type, "an SMS")
    if channel == "chat":
        return "a chat message from an unknown number"
    if channel == "url":
        return "a link checked on the page"
    if channel == "file":
        return "a file checked on the Pi"
    return "a message checked on the page"


class ScamLinks:
    """The watch list: written by the app, read by the network monitor."""

    def __init__(self, path=WATCH, clock=time.time):
        self.path, self.clock = path, clock
        self.sites, self.mtime, self.checked = {}, None, 0.0

    # --- the app's side ------------------------------------------------------------------
    def add(self, sites, verdict, category, where):
        """Watch these websites for 24 hours, from now."""
        if not sites or not self.path:
            return
        now_ms = int(self.clock() * 1000)
        data = {k: v for k, v in self._read().items() if v.get("until_ms", 0) > now_ms}
        for site in sites:
            data[site] = {"at_ms": now_ms, "until_ms": now_ms + KEEP_MS, "verdict": verdict,
                          "category": category, "where": where}
        if len(data) > MAX_SITES:                       # keep the newest
            data = dict(sorted(data.items(), key=lambda kv: kv[1]["at_ms"])[-MAX_SITES:])
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return {k: v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    # --- the monitor's side --------------------------------------------------------------
    def get(self, site, t_ms):
        """The message entry if `site` came in a flagged message and a lookup at t_ms counts:
        after the message arrived (1 minute of slack for clocks) and within 24 hours."""
        if not self.path:
            return None
        now = time.monotonic()
        if now - self.checked >= RELOAD_S:              # re-read only when the file changed
            self.checked = now
            try:
                mtime = os.path.getmtime(self.path)
            except OSError:
                mtime = None
            if mtime != self.mtime:
                self.mtime, self.sites = mtime, (self._read() if mtime is not None else {})
        e = self.sites.get(site)
        if e and e.get("at_ms", 0) - 60_000 <= t_ms < e.get("until_ms", 0):
            return e
        return None

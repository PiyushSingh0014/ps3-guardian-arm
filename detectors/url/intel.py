"""Known phishing and malware sites from public lists, kept on the device.

scripts/get_url_data.py downloads the lists and calls build() to write a small SQLite
file (data/url/intel.sqlite), so a lookup needs no network and almost no memory.

  * Phishing.Database (Mitchell Krog, Nissar Chababy; MIT licence): phishing domains
    that were still online when last tested, updated daily.
  * Any other list you download yourself under its own terms (OpenPhish's community
    feed, abuse.ch URLhaus with an account): get_url_data.py --extra name=path.

A link matches when its host, or the registered domain it belongs to, is on a list.
Services where anyone can publish (free hosting, shared files and forms), link
shorteners, chat links and official sites are never matched as a whole: one bad page
on docs.google.com must not block every Google Doc.
"""
import os
import sqlite3
import threading
import time

from .links import parse_link
from .lists import (BRAND_DOMAINS, BRAND_INFRA, CHAT_HOSTS, FREE_HOSTING, OFFICIAL_ZONES, SHARED_CONTENT,
                    SHORTENERS)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB = os.path.join(ROOT, "data", "url", "intel.sqlite")

# Entries that would block a whole service if they were matched as a registered domain.
_NEVER_WHOLE = FREE_HOSTING | SHARED_CONTENT | SHORTENERS | CHAT_HOSTS | set(BRAND_DOMAINS) | BRAND_INFRA


def entry_host(line):
    """One line of a list (a domain or a full link) -> the host to store, or None."""
    line = line.strip()
    if not line or line.startswith(("#", "!", ";")):
        return None
    if "://" not in line and "/" not in line and " " not in line:
        line = "http://" + line                  # a bare domain: parse it as an explicit link
    link = parse_link(line)
    if link is None:
        return None
    return link.host


def is_protected(host):
    """True for hosts that must never be listed as a whole (official sites, shared services)."""
    if host in _NEVER_WHOLE:
        return True
    if any(host == z or host.endswith("." + z) for z in OFFICIAL_ZONES):
        return True
    link = parse_link("http://" + host)
    return bool(link and link.registered == host and link.registered in _NEVER_WHOLE)


def build(sources, out=DB, allow=()):
    """sources: {name: iterable of lines}; allow: registered domains never to list.

    The public lists contain mistakes and abused pages of big sites (one Amazon country
    site, Instagram's link redirector); passing the most visited websites as `allow`
    keeps those out. Returns {name: number of hosts stored}.
    """
    allow = set(allow)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    tmp = out + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute("CREATE TABLE bad (host TEXT PRIMARY KEY, source TEXT NOT NULL) WITHOUT ROWID")
    con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    counts = {}
    for name, lines in sources.items():
        rows = set()
        for line in lines:
            host = entry_host(line)
            if not host or is_protected(host):
                continue
            link = parse_link("http://" + host)
            if link and (link.registered in allow or host in allow):
                continue
            rows.add(host)
        con.executemany("INSERT OR IGNORE INTO bad VALUES (?, ?)", ((h, name) for h in rows))
        counts[name] = len(rows)
    con.executemany("INSERT INTO meta VALUES (?, ?)",
                    [("built", time.strftime("%Y-%m-%d %H:%M")), ("sources", ",".join(sources))])
    con.commit()
    con.close()
    os.replace(tmp, out)
    return counts


class Blocklist:
    """Read-only lookups in the SQLite file; empty (never matches) if the file is missing."""

    RECHECK_S = 600            # look for a newer file (get_url_data.py) every 10 minutes

    def __init__(self, path=DB):
        self.path = path
        self.lock = threading.Lock()
        self.con, self.mtime, self.checked = None, None, 0.0
        self._open()

    def _open(self):
        self.checked = time.time()
        if not self.path or not os.path.exists(self.path):
            return
        mtime = os.path.getmtime(self.path)
        if self.con is not None and mtime == self.mtime:
            return
        con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        old, self.con, self.mtime = self.con, con, mtime
        if old is not None:
            old.close()

    def __bool__(self):
        return self.con is not None

    def info(self):
        if self.con is None:
            return {"loaded": False}
        with self.lock:
            n = self.con.execute("SELECT COUNT(*) FROM bad").fetchone()[0]
            meta = dict(self.con.execute("SELECT key, value FROM meta").fetchall())
        return {"loaded": True, "hosts": n, **meta}

    def lookup(self, link):
        """The list a link is on, or None."""
        if link is None:
            return None
        keys = [link.host]
        if link.registered and link.registered != link.host and link.registered not in _NEVER_WHOLE:
            keys.append(link.registered)
        with self.lock:
            if time.time() - self.checked > self.RECHECK_S:
                self._open()
            if self.con is None:
                return None
            for k in keys:
                row = self.con.execute("SELECT source FROM bad WHERE host = ?", (k,)).fetchone()
                if row:
                    return row[0]
        return None

#!/usr/bin/python3 -I
"""PS3 Guardian: the Pi's DNS block list for dnsmasq (update 40).

Installed by scripts/setup_dns_block.sh as /usr/local/lib/ps3-guardian/dns-block and run as root by
ps3-dnsblock.service: whenever the app's list (data/net/blocklist.json) changes (ps3-dnsblock.path),
and every hour, so that blocks end on time (ps3-dnsblock.timer). It takes no arguments.

It reads only the paths in /etc/ps3-guardian/dns-block.json, a file only root can change. It keeps
only well-formed website names from the list, at most 1,000, and writes them as dnsmasq
"server=/name/" lines: the hotspot's dnsmasq then answers NXDOMAIN for the name and every name under
it. Then it sends SIGHUP to that dnsmasq, which reads the file again and empties its cache. It writes
nothing else and runs nothing else.
"""
import json
import os
import pwd
import re
import signal
import stat
import sys
import time

CONF = os.environ.get("PS3_DNSBLOCK_CONF", "/etc/ps3-guardian/dns-block.json")
SHARED_DIR = "/etc/NetworkManager/dnsmasq-shared.d"
MAX_NAMES = 1000
MAX_BYTES = 1_000_000
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
NAME_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")


def read_list(path, owner_uid):
    """The list's names, if the file is a regular file of the app's user (not a link), else []."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or st.st_size > MAX_BYTES:
            raise ValueError(f"{path} is not a regular file of the app's user, or is too big")
        data = json.loads(os.read(fd, MAX_BYTES + 1).decode("utf-8"))
    finally:
        os.close(fd)
    now_ms = time.time() * 1000
    blocked = data.get("blocked") if isinstance(data, dict) else None
    names = []
    for name, e in (blocked or {}).items():
        if not isinstance(e, dict) or not isinstance(name, str):
            continue
        until = e.get("until_ms")
        if until is not None and (not isinstance(until, (int, float)) or until <= now_ms):
            continue
        if len(name) <= 253 and NAME_RE.match(name):
            names.append((e.get("since_ms", 0) if isinstance(e.get("since_ms"), (int, float)) else 0, name))
    return [n for _, n in sorted(names, reverse=True)[:MAX_NAMES]]


def write_servers(path, names):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        f.write("# Written by /usr/local/lib/ps3-guardian/dns-block (PS3 Guardian): websites the Pi does not\n"
                "# look up for the devices on its hotspot. Edit the list on the Pi's page, not this file.\n")
        f.writelines(f"server=/{n}/\n" for n in sorted(names))
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def hotspot_dnsmasq():
    """Process ids of the dnsmasq NetworkManager runs for its hotspot (reads dnsmasq-shared.d)."""
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                args = f.read().split(b"\0")
        except OSError:
            continue
        if args and os.path.basename(args[0]) == b"dnsmasq" and any(SHARED_DIR.encode() in a for a in args):
            pids.append(int(entry))
    return pids


def main():
    with open(CONF, encoding="utf-8") as f:
        conf = json.load(f)
    uid = pwd.getpwnam(conf["owner"]).pw_uid
    names = []
    for _ in range(3):                            # the list may change while this runs
        before = os.stat(conf["list"]).st_mtime if os.path.exists(conf["list"]) else None
        try:
            names = read_list(conf["list"], uid)
        except (OSError, ValueError, UnicodeDecodeError) as e:
            print(f"ps3-dnsblock: cannot use the list ({e}); the old one stays", file=sys.stderr)
            return 1
        write_servers(conf["servers"], names)
        after = os.stat(conf["list"]).st_mtime if os.path.exists(conf["list"]) else None
        if after == before:
            break
    pids = hotspot_dnsmasq()
    for pid in pids:
        os.kill(pid, signal.SIGHUP)
    print(f"ps3-dnsblock: {len(names)} websites blocked; "
          + (f"the hotspot's DNS (dnsmasq {', '.join(map(str, pids))}) read them again"
             if pids else "the hotspot is off: its DNS reads them when it starts"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

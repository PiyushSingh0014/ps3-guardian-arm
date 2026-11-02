"""Watch a network interface (or read a capture file) and write network alerts.

    python -m detectors.net.monitor --iface wlan0          # live, on the Pi's own Wi-Fi
    python -m detectors.net.monitor --pcap capture.pcap    # a capture file
    python -m detectors.net.monitor --cic Friday.csv       # labelled CIC-IDS2017 flows

Alerts go to logs/net_alerts.jsonl, one JSON object per line; the app shows them under
"Network alerts" (GET /alerts). Live capture needs the CAP_NET_RAW and CAP_NET_ADMIN
capabilities: scripts/install_netmon.sh runs this as a systemd service that has them.
Only alerts and what baseline.py keeps per device (counts, names of the servers it uses)
are kept, never packet contents. When live, a status line goes to the log every 15 minutes.
"""
import argparse
import json
import os
import signal
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.net.engine import NetEngine, default_state_path       # noqa: E402
from detectors.net.flows import read_cic_csv, read_flows             # noqa: E402
from detectors.net.scamlinks import WATCH                             # noqa: E402

ALERTS = os.path.join(ROOT, "logs", "net_alerts.jsonl")
SAVE_EVERY_S = 600
STATUS_EVERY_S = 900                         # live only: "[net] 19:30 1234 flows so far ..."
FIRST_STATUS_S = 60                          # the first one a minute after starting


def iface_address(iface):
    try:
        import psutil
        for a in psutil.net_if_addrs().get(iface, []):
            if a.family == 2:                     # AF_INET
                return a.address
    except Exception:
        pass
    return None


def write_alert(path, finding):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    f = finding.to_dict()
    f.pop("raw_text", None)
    line = {"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f["entities"].get("time_ms", 0) / 1000)),
            "finding": f}
    with open(path, "a", encoding="utf-8") as out:
        out.write(json.dumps(line, ensure_ascii=False) + "\n")


_MAIN = os.getpid()


def _interrupt(*_):
    if os.getpid() != _MAIN:                 # NFStream's capture processes inherit this handler
        os._exit(0)
    raise KeyboardInterrupt                  # systemctl stop: end the capture cleanly, like Ctrl+C


def run(flows, engine, out=None, show=True, iface=None):
    """Feed flows to the engine; write and print alerts. With `iface` (live), also print a
    status line now and then, and learn the Pi's address there if it had none at start."""
    global _MAIN
    _MAIN = os.getpid()
    try:
        signal.signal(signal.SIGTERM, _interrupt)
    except ValueError:                       # not the main thread (tests)
        pass
    n_alerts, last_save = 0, time.time() - SAVE_EVERY_S + 60     # the first save after a minute
    since, next_status, flows_then = time.time(), time.time() + FIRST_STATUS_S, 0
    try:
        for rec in flows:
            for f in engine.feed(rec):
                n_alerts += 1
                if out:
                    write_alert(out, f)
                if show:
                    e = f.entities
                    who = e.get("device_name") or e.get("device")
                    print(f"[{f.verdict:10s}] {f.category:16s} {who} -> {e.get('peer')}: {f.reasons[0]}", flush=True)
            if time.time() - last_save > SAVE_EVERY_S:
                engine.save()
                last_save = time.time()
            now = time.time()
            if iface and now >= next_status:
                if engine.gateway is None:           # the Wi-Fi had no address when this started
                    engine.set_gateway(iface_address(iface))
                minutes = max(1, round((now - since) / 60))
                print(f"[net] {time.strftime('%H:%M')} {engine.flows} flows so far ({engine.flows - flows_then} "
                      f"in the last {minutes} min), {n_alerts} alerts", flush=True)
                since, next_status, flows_then = now, now + STATUS_EVERY_S, engine.flows
    except KeyboardInterrupt:
        pass
    finally:
        engine.save()
    return n_alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="network interface to watch, e.g. wlan0")
    src.add_argument("--pcap", help="capture file to read")
    src.add_argument("--cic", nargs="+", help="CIC-IDS2017 GeneratedLabelledFlows CSV file(s)")
    ap.add_argument("--out", default=None, help=f"alerts file (default {os.path.relpath(ALERTS, ROOT)} when live)")
    ap.add_argument("--learn-hours", type=float, default=2.0, help="learning time per device")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if a.iface:
        gateway = iface_address(a.iface)
        engine = NetEngine(gateway=gateway, learn_ms=int(a.learn_hours * 3600_000), state_path=default_state_path(),
                           watch_path=os.environ.get("NET_WATCH", WATCH))     # links from flagged messages
        print(f"[net] watching {a.iface} (this Pi is {gateway or 'unknown'}); alerts -> {a.out or ALERTS}", flush=True)
        n = run(read_flows(a.iface), engine, a.out or ALERTS, not a.quiet, iface=a.iface)
    elif a.pcap:
        engine = NetEngine(learn_ms=int(a.learn_hours * 3600_000), leases=None)
        n = run(read_flows(a.pcap), engine, a.out, not a.quiet)
    else:
        engine = NetEngine(learn_ms=int(a.learn_hours * 3600_000), leases=None)
        flows = (r for path in a.cic for r in read_cic_csv(path))
        n = run(flows, engine, a.out, not a.quiet)
    print(f"[net] {engine.flows} flows, {n} alerts", flush=True)


if __name__ == "__main__":
    main()

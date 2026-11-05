"""Watch a network interface (or read a capture file) and write network alerts.

    python -m detectors.net.monitor --iface wlan0          # live, on the Pi's own Wi-Fi
    python -m detectors.net.monitor --pcap capture.pcap    # a capture file
    python -m detectors.net.monitor --cic Friday.csv       # labelled CIC-IDS2017 flows

Alerts go to logs/net_alerts.jsonl, one JSON object per line; the app shows them under
"Network alerts" (GET /alerts). Live capture needs the CAP_NET_RAW and CAP_NET_ADMIN
capabilities: scripts/install_netmon.sh runs this as a systemd service that has them.
Only alerts and what baseline.py keeps per device (counts, names of the servers it uses)
are kept, never packet contents. When live, a status line goes to the log every 15 minutes,
and the watched time goes to data/net/days.json every 5 minutes, quiet or not.
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.net.engine import NetEngine, default_state_path       # noqa: E402
from detectors.net.flows import read_cic_csv, read_flows             # noqa: E402
from detectors.net.scamlinks import WATCH                             # noqa: E402

ALERTS = os.path.join(ROOT, "logs", "net_alerts.jsonl")
DAYS = os.path.join(ROOT, "data", "net", "days.json")    # watched time, flows, alerts per day
SAVE_EVERY_S = 600
STATUS_EVERY_S = 900                         # live only: "[net] 19:30 1234 flows so far ..."
FIRST_STATUS_S = 60                          # the first one a minute after starting
TICK_S = 300                                 # live only: watched time to days.json, quiet or not
STUCK_PACKETS = 300                          # Wi-Fi packets in a stretch with no flow at all...
STUCK_TICKS = 2                              # ...this many stretches in a row: the capture is stuck
CAPTURE_STUCK = threading.Event()            # set when the capture was restarted for that reason


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


def iface_packets(iface):
    """Packets in and out of the interface since it came up; None if unreadable."""
    try:
        total = 0
        for name in ("rx_packets", "tx_packets"):
            with open(f"/sys/class/net/{iface}/statistics/{name}") as f:
                total += int(f.read())
        return total
    except (OSError, ValueError):
        return None


def iface_up(iface):
    """False when the interface is down or gone (the hotspot is off): nothing to watch then."""
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            return f.read().strip() not in ("down", "notpresent", "lowerlayerdown")
    except OSError:
        return False


def next_midnight(t):
    lt = time.localtime(t)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + 1, 0, 0, 0, 0, 0, -1))


def add_day(path, minutes, flows, alerts, day=None, active=None):
    """Add one stretch of watching to data/net/days.json: minutes, flows and alerts per day, and
    `active` minutes, the part of it with traffic. scripts/net_traffic.py turns it into false
    alarms per day."""
    day = day or time.strftime("%Y-%m-%d")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        data = {}
    d = data.setdefault(day, {})
    d["minutes"] = round(d.get("minutes", 0) + minutes, 2)
    if active is not None:
        d["active_minutes"] = round(d.get("active_minutes", 0) + active, 2)
    d["flows"] = d.get("flows", 0) + flows
    d["alerts"] = d.get("alerts", 0) + alerts
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


class WatchedTime:
    """Live only: the status line, and the watched time, flows and alerts per day in
    data/net/days.json. It runs on a clock of its own, every TICK_S and at midnight, so quiet
    hours are written down too and each day gets its own time. (Until update 26 this happened
    only when a flow arrived: a quiet night or two then went to the next day all at once.)

    A stretch counts as watched only while the Wi-Fi is up and the capture works. When the Wi-Fi
    carries packets but the capture reports no flow at all, STUCK_TICKS times in a row, the
    capture is stuck: tick() returns True and the monitor restarts (systemd starts it again)."""

    def __init__(self, engine, iface, days=None, show=True, clock=time.time, packets=None, up=None):
        self.engine, self.iface, self.days, self.show, self.clock = engine, iface, days, show, clock
        self.packets, self.up = packets or iface_packets, up or iface_up
        self.alerts = 0                                   # the flow loop adds every alert here
        self.lock, self.stopped = threading.Lock(), threading.Event()
        now = clock()
        self.since, self.flows_then, self.alerts_then = now, engine.flows, 0
        self.packets_then = self.packets(iface)
        self.status_since, self.status_flows, self.next_status = now, engine.flows, now + FIRST_STATUS_S
        self.silent_ticks, self.stuck = 0, False

    def wait_s(self):
        """Seconds to the next tick: TICK_S at most, and never across midnight or a status line."""
        now = self.clock()
        return max(1.0, min(TICK_S, next_midnight(now) + 1 - now, self.next_status - now))

    def tick(self, final=False):
        """Close the stretch since the last tick and add it to its day. True: the capture is stuck."""
        with self.lock:
            now = self.clock()
            flows, alerts = self.engine.flows - self.flows_then, self.alerts - self.alerts_then
            packets = self.packets(self.iface)
            moved = None if packets is None or self.packets_then is None else max(0, packets - self.packets_then)
            minutes = max(0.0, (now - self.since) / 60)
            silent = (not final and flows == 0 and moved is not None and moved >= STUCK_PACKETS
                      and minutes >= 2)
            self.silent_ticks = self.silent_ticks + 1 if silent else 0
            up = self.up(self.iface)
            hhmm = time.strftime("%H:%M", time.localtime(now))
            if self.days and up and not silent and not self.stuck and minutes > 0:
                try:
                    add_day(self.days, minutes, flows, alerts, active=minutes if flows else 0,
                            day=time.strftime("%Y-%m-%d", time.localtime(self.since)))
                except OSError as e:
                    print(f"[net] could not write {self.days}: {e}", flush=True)
            self.since, self.flows_then, self.alerts_then, self.packets_then = (
                now, self.engine.flows, self.alerts, packets)
            if self.show and (final or now >= self.next_status):
                mins = max(1, round((now - self.status_since) / 60))
                print(f"[net] {hhmm} {self.engine.flows} flows so far ({self.engine.flows - self.status_flows} "
                      f"in the last {mins} min), {self.alerts} alerts"
                      + ("" if up else " (the Wi-Fi is off: not counted as watched)"), flush=True)
                self.status_since, self.status_flows = now, self.engine.flows
                self.next_status = now + STATUS_EVERY_S
            if silent:
                self.stuck = self.silent_ticks >= STUCK_TICKS
                print(f"[net] {hhmm} the Wi-Fi carried {moved} packets in {minutes:.0f} min but the capture "
                      "saw no flow" + (": restarting the capture" if self.stuck else ""), flush=True)
            return self.stuck

    def start(self, on_stuck=None):
        def loop():
            while not self.stopped.wait(self.wait_s()):
                if self.tick():
                    (on_stuck or self.restart)()
                    return
        threading.Thread(target=loop, daemon=True, name="watched-time").start()

    def restart(self):
        CAPTURE_STUCK.set()
        os.kill(os.getpid(), signal.SIGTERM)       # the flow loop ends cleanly; main exits with 3
        if not self.stopped.wait(30):
            os._exit(3)                             # it did not end: leave anyway

    def stop(self):
        self.stopped.set()


_MAIN = os.getpid()


def _interrupt(*_):
    if os.getpid() != _MAIN:                 # NFStream's capture processes inherit this handler
        os._exit(0)
    raise KeyboardInterrupt                  # systemctl stop: end the capture cleanly, like Ctrl+C


def run(flows, engine, out=None, show=True, iface=None, days=None):
    """Feed flows to the engine; write and print alerts. With `iface` (live), also learn the
    Pi's address there if it had none at start, and keep the status line and the watched time
    per day (`days`) on a clock of their own (WatchedTime)."""
    global _MAIN
    _MAIN = os.getpid()
    try:
        signal.signal(signal.SIGTERM, _interrupt)
    except ValueError:                       # not the main thread (tests)
        pass
    n_alerts, last_save = 0, time.time() - SAVE_EVERY_S + 60     # the first save after a minute
    next_gateway = time.time() + FIRST_STATUS_S
    watch = WatchedTime(engine, iface, days, show=show) if iface else None
    if watch:
        watch.start()
    try:
        for rec in flows:
            for f in engine.feed(rec):
                n_alerts += 1
                if watch:
                    watch.alerts += 1
                if out:
                    write_alert(out, f)
                if show:
                    e = f.entities
                    who = e.get("device_name") or e.get("device")
                    print(f"[{f.verdict:10s}] {f.category:16s} {who} -> {e.get('peer')}: {f.reasons[0]}", flush=True)
            if time.time() - last_save > SAVE_EVERY_S:
                engine.save()
                last_save = time.time()
            if iface and engine.gateway is None and time.time() >= next_gateway:
                engine.set_gateway(iface_address(iface))  # the Wi-Fi had no address when this started
                next_gateway = time.time() + 60
    except KeyboardInterrupt:
        pass
    finally:
        engine.save()
        if watch:
            watch.stop()
            watch.tick(final=True)
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
        n = run(read_flows(a.iface), engine, a.out or ALERTS, not a.quiet, iface=a.iface, days=DAYS)
    elif a.pcap:
        engine = NetEngine(learn_ms=int(a.learn_hours * 3600_000), leases=None)
        n = run(read_flows(a.pcap), engine, a.out, not a.quiet)
    else:
        engine = NetEngine(learn_ms=int(a.learn_hours * 3600_000), leases=None)
        flows = (r for path in a.cic for r in read_cic_csv(path))
        n = run(flows, engine, a.out, not a.quiet)
    print(f"[net] {engine.flows} flows, {n} alerts", flush=True)
    if CAPTURE_STUCK.is_set():
        sys.exit(3)                          # systemd starts the monitor again (Restart=always)


if __name__ == "__main__":
    main()

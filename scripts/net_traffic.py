"""Measure the network detector on real traffic: false alarms per day on the lab Wi-Fi.

1. Export the monitor's alerts (logs/net_alerts.jsonl) to a sheet. Run it on the Pi:
       python scripts/net_traffic.py export alerts.csv
   Alerts that came while the ESP32 ran a test mode are labelled 'test' already: the Pi
   logs every test started from its page (logs/lab_tests.jsonl).
2. Open alerts.csv in Excel and fill the empty 'label' cells:
       test   you caused it on purpose (the laptop's look-ups, a scam link you opened as a test)
       false  a false alarm: nothing was wrong
       real   a real problem
   Leave a cell empty if unsure.
3. Measure watched time and false alarms per day, by kind and by device:
       python scripts/net_traffic.py measure alerts.csv
   Watched time and flows come from data/net/days.json, which the monitor keeps since
   update 24, so days before that have alerts but no hours.
"""
import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLUMNS = ["id", "time", "device", "device_name", "kind", "verdict", "peer", "reason", "label", "notes"]
LABELS = ("test", "false", "real")
AFTER_TEST_MS = 10 * 60_000       # alerts this soon after a test still belong to it


def read_jsonl(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    return out


def test_windows(path):
    """[(device address, start ms, end ms, mode)] of the test modes started from the Pi's page."""
    out, running = [], {}
    for e in sorted(read_jsonl(path), key=lambda e: e.get("time_ms", 0)):
        name, t = e.get("device"), e.get("time_ms", 0)
        if name in running:                          # a new mode, or "normal", ends the running test
            ip, start, planned, mode = running.pop(name)
            out.append((ip, start, min(planned, t), mode))
        if e.get("mode") not in (None, "normal"):
            running[name] = (e.get("ip", ""), t, t + int(e.get("seconds", 0)) * 1000, e["mode"])
    out += list(running.values())
    return out


def export(alerts_path, tests_path, out_path):
    windows = test_windows(tests_path)
    rows = []
    for item in read_jsonl(alerts_path):
        f = item.get("finding") or {}
        e = f.get("entities") or {}
        ip, t = e.get("device", ""), e.get("time_ms", 0)
        test = next((w for w in windows if w[0] == ip and w[1] <= t <= w[2] + AFTER_TEST_MS), None)
        rows.append({
            "id": hashlib.sha1(json.dumps(item, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:16],
            "time": item.get("time", ""), "device": ip, "device_name": e.get("device_name", ""),
            "kind": f.get("category", ""), "verdict": f.get("verdict", ""), "peer": e.get("peer", ""),
            "reason": (f.get("reasons") or [""])[0], "label": "test" if test else "",
            "notes": f"ESP32 test mode {test[3]}" if test else ""})
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel reads it as UTF-8
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    pre = sum(1 for r in rows if r["label"])
    print(f"Wrote {len(rows)} alerts to {out_path} ({pre} labelled 'test' from the ESP32's test modes). "
          "Fill the empty 'label' cells, then run 'measure'.")


def measure(sheet, days_path):
    with open(sheet, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["label"] = (r.get("label") or "").strip().lower()
        r["day"] = (r.get("time") or "")[:10]
    try:
        with open(days_path, encoding="utf-8") as f:
            days = json.load(f)
    except (OSError, ValueError):
        days = {}

    watched = {d: v for d, v in days.items() if isinstance(v, dict) and v.get("minutes", 0) > 0}
    hours = sum(v["minutes"] for v in watched.values()) / 60
    flows = sum(v.get("flows", 0) for v in watched.values())
    count = Counter(r["label"] for r in rows)
    print(f"Alerts: {len(rows)}: test {count['test']}, false {count['false']}, real {count['real']}, "
          f"not labelled {len(rows) - sum(count[k] for k in LABELS)}")
    print(f"Watched: {len(watched)} days with records, {hours:.1f} hours, {flows:,} flows")

    print("\n| Day | Hours watched | Flows | Alerts | Test | False | Real | Not labelled |")
    print("|---|---|---|---|---|---|---|---|")
    for day in sorted({r["day"] for r in rows} | set(watched)):
        t = [r for r in rows if r["day"] == day]
        c = Counter(r["label"] for r in t)
        v = watched.get(day)
        print(f"| {day} | {v['minutes'] / 60:.1f} |" if v else f"| {day} | ? |",
              f"{v.get('flows', 0):,} |" if v else "? |",
              f"{len(t)} | {c['test']} | {c['false']} | {c['real']} | {len(t) - sum(c[k] for k in LABELS)} |")

    false = [r for r in rows if r["label"] == "false" and r["day"] in watched]
    if hours:
        print(f"\nFalse alarms on the watched days: {len(false)} in {hours:.1f} hours = "
              f"{len(false) / hours * 24:.1f} per day")
    else:
        print("\nNo watched time recorded yet (data/net/days.json): false alarms per day need the monitor of update 24.")
    all_false = [r for r in rows if r["label"] == "false"]
    if all_false:
        print("False alarms by kind:", dict(Counter(r["kind"] for r in all_false).most_common()))
        print("False alarms by device:", dict(Counter(r["device_name"] or r["device"] for r in all_false).most_common()))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="alerts -> a sheet to label")
    e.add_argument("out")
    e.add_argument("--alerts", default=os.path.join(ROOT, "logs", "net_alerts.jsonl"))
    e.add_argument("--tests", default=os.path.join(ROOT, "logs", "lab_tests.jsonl"))
    m = sub.add_parser("measure", help="the labelled sheet -> false alarms per day")
    m.add_argument("sheet")
    m.add_argument("--days", default=os.path.join(ROOT, "data", "net", "days.json"))
    a = ap.parse_args()
    if a.cmd == "export":
        export(a.alerts, a.tests, a.out)
    else:
        measure(a.sheet, a.days)
    return 0


if __name__ == "__main__":
    sys.exit(main())

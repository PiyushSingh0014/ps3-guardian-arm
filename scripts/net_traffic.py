"""Measure the network detector on real traffic: false alarms per day on the lab Wi-Fi.

Run it on the Pi, from ~/ps3-guardian with the venv on, after the lab Wi-Fi has been in
normal use for a day or more. The monitor keeps the hours it watched per day
(data/net/days.json); the app logs every test started from its page (logs/lab_tests.jsonl).

1. Say what each alert was, right in the terminal:
       python scripts/net_traffic.py label
   It shows the alerts of the days the monitor watched, one at a time. Type
       t   test: you caused it on purpose (a website you looked up as a test, a test you started)
       f   false alarm: nothing was wrong
       r   real: a real problem
   Enter on its own skips one, q stops. Each answer is saved at once (data/net/labels.json), so
   you can stop and carry on later. Alerts that came while the ESP32 ran a test mode are
   labelled 'test' already.
2. Count watched time and false alarms per day, by kind and by device:
       python scripts/net_traffic.py measure

In a spreadsheet instead: `export alerts.csv` writes every alert with its label so far; fill the
'label' column (test, false or real) and run `measure alerts.csv`. The sheet may go through
Excel: each row is matched to the alert log by its id, so a date Excel re-wrote in its own
format still counts on the right day, and a sheet saved in the Windows code page still reads.
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS = os.path.join(ROOT, "logs", "net_alerts.jsonl")
TESTS = os.path.join(ROOT, "logs", "lab_tests.jsonl")
DAYS = os.path.join(ROOT, "data", "net", "days.json")
LABELS_FILE = os.path.join(ROOT, "data", "net", "labels.json")
PLAYBOOKS = os.path.join(ROOT, "advisor", "playbooks")
COLUMNS = ["id", "time", "device", "device_name", "kind", "verdict", "peer", "reason", "label", "notes"]
LABELS = ("test", "false", "real")
WORDS = {"t": "test", "test": "test", "f": "false", "false": "false", "false alarm": "false",
         "r": "real", "real": "real"}
AFTER_TEST_MS = 10 * 60_000       # alerts this soon after a test still belong to it
QUIET_FLOWS_PER_HOUR = 300        # fewer: the Wi-Fi was hardly used (a laptop in use makes thousands)
MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                      "nov", "dec"), 1)}
LEGEND = """For each alert, type a letter and press Enter:
  t   test: you caused it on purpose (a website you looked up as a test, a test you started)
  f   false alarm: nothing was wrong
  r   real: a real problem
Enter on its own skips an alert you are not sure about; q stops.
Each answer is saved at once, so you can stop and carry on later."""


def n_of(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def show(path):
    """A path as the person typed it from ~/ps3-guardian."""
    rel = os.path.relpath(os.path.abspath(path), ROOT)
    return path if rel.startswith("..") else rel


def read_jsonl(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    out.append(item)
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


def alert_id(item):
    """16 hex characters of the app's alert key: the same alert always gets the same id."""
    return hashlib.sha1(json.dumps(item, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:16]


def norm_label(text):
    """'test', 'false' or 'real' from what a person typed (t, F, FALSE, false alarm...); '' if none."""
    return WORDS.get(" ".join(str(text or "").strip().lower().split()), "")


def load_labels(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if v in LABELS} if isinstance(data, dict) else {}


def save_labels(path, labels):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def watched_days(path):
    """{day: {minutes, flows, alerts}} for the days the monitor watched (data/net/days.json)."""
    try:
        with open(path, encoding="utf-8") as f:
            days = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(days, dict):
        return {}
    return {d: v for d, v in days.items()
            if isinstance(v, dict) and isinstance(v.get("minutes"), (int, float)) and v["minutes"] > 0}


def load_alerts(alerts_path, tests_path, labels_path):
    """Every alert in the monitor's log, in its order, with its label: yours (from 'label'),
    else 'test' when an ESP32 test mode was running on that device."""
    windows = test_windows(tests_path)
    stored = load_labels(labels_path)
    out = []
    for item in read_jsonl(alerts_path):
        f = item.get("finding") if isinstance(item.get("finding"), dict) else {}
        e = f.get("entities") if isinstance(f.get("entities"), dict) else {}
        ip, t = str(e.get("device", "")), e.get("time_ms", 0)
        t = t if isinstance(t, (int, float)) else 0
        aid = alert_id(item)
        test = next((w for w in windows if w[0] == ip and w[1] <= t <= w[2] + AFTER_TEST_MS), None)
        when = str(item.get("time") or "")
        out.append({"id": aid, "time": when, "day": when[:10], "device": ip,
                    "device_name": str(e.get("device_name", "")), "kind": str(f.get("category", "")),
                    "verdict": str(f.get("verdict", "")), "peer": str(e.get("peer", "")),
                    "reasons": [str(r) for r in (f.get("reasons") or [])],
                    "label": stored.get(aid) or ("test" if test else ""),
                    "by": "you" if aid in stored else ("esp32" if test else ""),
                    "notes": f"ESP32 test mode {test[3]}" if test else ""})
    return out


_TITLES = {}


def title_of(kind):
    """The playbook's title for an alert kind, as the page shows it."""
    if kind not in _TITLES:
        title = (kind or "alert").replace("_", " ")
        if re.fullmatch(r"[a-z0-9_]{1,40}", kind or ""):
            try:
                with open(os.path.join(PLAYBOOKS, kind + ".md"), encoding="utf-8") as f:
                    m = re.search(r"^#\s+(.+)$", f.read(), re.M)
                if m:
                    title = m.group(1).strip()
            except OSError:
                pass
        _TITLES[kind] = title
    return _TITLES[kind]


def who(a):
    name, ip = a.get("device_name") or "", a.get("device") or ""
    return f"{name} ({ip})" if name and ip and name != ip else (name or ip or "unknown device")


def label(alerts_path=ALERTS, tests_path=TESTS, labels_path=LABELS_FILE, days_path=DAYS,
          everything=False, again=False, ask=input, say=print):
    """Go through the alerts one at a time in the terminal and save what the person says each was."""
    watched = watched_days(days_path)
    alerts = load_alerts(alerts_path, tests_path, labels_path)
    if everything:
        scope = "all days"
    else:
        if not watched:
            say(f"The monitor has no watched days yet ({show(days_path)}). Leave it running on the lab "
                "Wi-Fi for a day first, or add --all to go through every alert.")
            return
        alerts = [a for a in alerts if a["day"] in watched]
        days = sorted(watched)
        scope = (f"the days the monitor watched ({days[0]} to {days[-1]})" if len(days) > 1
                 else f"the day the monitor watched ({days[0]})")
    stored = load_labels(labels_path)
    todo = [a for a in alerts if again or not a["label"]]
    say(f"{n_of(len(alerts), 'alert')} on {scope}.")
    say(f"Labelled already: {sum(a['by'] == 'esp32' for a in alerts)} during ESP32 tests, "
        f"{sum(a['by'] == 'you' for a in alerts)} by you. To go: {len(todo)}.")
    if not todo:
        say("\nNothing to label. Next: python scripts/net_traffic.py measure")
        return
    say("\n" + LEGEND)
    answered = Counter()
    try:
        for i, a in enumerate(todo, 1):
            say("")
            say(f"[{i} of {len(todo)}]  {a['time'] or 'time unknown'}   {who(a)}")
            say(f"  {(a['verdict'] or 'alert').upper()}: {title_of(a['kind'])}")
            for reason in a["reasons"][:3]:
                say(f"  - {reason}")
            if a["label"]:
                say(f"  Label now: {a['label']} (Enter keeps it)")
            answer = None
            while answer is None:
                try:
                    typed = " ".join(str(ask("  t / f / r: ")).strip().lower().split())
                except EOFError:
                    typed = "q"
                if typed in ("q", "quit", "stop", "exit"):
                    raise KeyboardInterrupt
                if typed == "":
                    answer = ""
                elif norm_label(typed):
                    answer = norm_label(typed)
                    stored[a["id"]] = answer
                    save_labels(labels_path, stored)
                    answered[answer] += 1
                else:
                    say("  Type t, f or r. Enter on its own skips it; q stops.")
    except KeyboardInterrupt:
        say("\nStopped.")
    n = sum(answered.values())
    say("")
    say(f"Saved {n_of(n, 'answer')} in {show(labels_path)}"
        + (f" ({', '.join(f'{k} {v}' for k, v in answered.most_common())})" if n else "") + ".")
    left = sum(1 for a in todo if not (stored.get(a["id"]) or a["by"] == "esp32"))
    if left:
        say(f"{n_of(left, 'alert')} still without a label: run python scripts/net_traffic.py label "
            f"again to go through {'it' if left == 1 else 'them'}.")
    say("Next: python scripts/net_traffic.py measure")


def export(alerts_path, tests_path, out_path, labels_path=LABELS_FILE, say=print):
    rows = load_alerts(alerts_path, tests_path, labels_path)
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel reads it as UTF-8
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({**r, "reason": (r["reasons"] or [""])[0]})
    say(f"Wrote {len(rows)} alerts to {out_path} ({sum(r['by'] == 'esp32' for r in rows)} labelled 'test' "
        f"from the ESP32's test modes, {sum(r['by'] == 'you' for r in rows)} labelled by you). "
        f"Fill the empty 'label' cells, then run 'measure {os.path.basename(out_path)}'.")


def read_sheet(path):
    """The rows of a sheet from 'export', also after Excel saved it (Windows code page, ';' lists)."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")       # Excel's "CSV (Comma delimited)"
    head = text.split("\n", 1)[0]
    delimiter = ";" if head.count(";") > head.count(",") else ","
    return list(csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter))


def _date(y, m, d):
    try:
        return datetime.date(y, m, d).isoformat()
    except ValueError:
        return None


def day_of(text, known=()):
    """The day of a time as we write it (2026-11-03 10:05:00) or as Excel re-writes it
    (03-11-2026 10:05 in India, 11/3/2026 10:05 AM in the US, 03-Nov-26). Where day and month
    could be swapped, a day the monitor watched or logged alerts on wins; else day first."""
    s = str(text or "").strip()
    m = re.match(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
    if m:
        return _date(*map(int, m.groups())) or ""
    m = re.match(r"(\d{1,2})[-/. ]([A-Za-z]{3})[A-Za-z]*[-/., ]+(\d{2,4})", s)
    if m and m.group(2).lower() in MONTHS:
        y = int(m.group(3))
        return _date(y + 2000 if y < 100 else y, MONTHS[m.group(2).lower()], int(m.group(1))) or ""
    m = re.match(r"([A-Za-z]{3})[A-Za-z]*[-/. ](\d{1,2}),?[-/. ]+(\d{2,4})", s)
    if m and m.group(1).lower() in MONTHS:
        y = int(m.group(3))
        return _date(y + 2000 if y < 100 else y, MONTHS[m.group(1).lower()], int(m.group(2))) or ""
    m = re.match(r"(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})", s)
    if not m:
        return ""
    a, b, y = map(int, m.groups())
    y = y + 2000 if y < 100 else y
    options = []
    for d, mo in ((a, b), (b, a)):                  # day first (India, UK), then month first (US)
        x = _date(y, mo, d)
        if x and x not in options:
            options.append(x)
    seen = [x for x in options if x in known]
    return seen[0] if len(seen) == 1 else (options[0] if options else "")


def rows_from_sheet(sheet, log, known):
    """The sheet's rows with their labels; the day comes from the alert log when the id matches."""
    by_id = {a["id"]: a for a in log}
    rows, odd, matched = [], Counter(), 0
    for r in read_sheet(sheet):
        if not any(isinstance(v, str) and v.strip() for v in r.values()):
            continue                                           # an empty line Excel left
        raw = (r.get("label") or "").strip()
        lab = norm_label(raw)
        if raw and not lab:
            odd[raw] += 1
        a = by_id.get((r.get("id") or "").strip())
        if a:
            matched += 1
            rows.append({**a, "label": lab})
        else:
            rows.append({"id": r.get("id") or "", "time": r.get("time") or "", "day": day_of(r.get("time"), known),
                         "device": r.get("device") or "", "device_name": r.get("device_name") or "",
                         "kind": r.get("kind") or "", "verdict": r.get("verdict") or "", "label": lab})
    return rows, odd, matched


def measure(sheet=None, days_path=DAYS, alerts_path=ALERTS, tests_path=TESTS, labels_path=LABELS_FILE,
            everything=False, say=print):
    watched = watched_days(days_path)
    log = load_alerts(alerts_path, tests_path, labels_path)
    odd, matched = Counter(), 0
    if sheet:
        rows, odd, matched = rows_from_sheet(sheet, log, set(watched) | {a["day"] for a in log})
    else:
        rows = log
    shown = rows if everything else [r for r in rows if r["day"] in watched]
    hidden = [] if everything else [r for r in rows if r["day"] not in watched]

    hours = sum(v["minutes"] for v in watched.values()) / 60
    flows = sum(v.get("flows", 0) for v in watched.values())
    count = Counter(r["label"] for r in shown)
    say(f"Alerts: {len(shown)}: test {count['test']}, false {count['false']}, real {count['real']}, "
        f"not labelled {len(shown) - sum(count[k] for k in LABELS)}")
    say(f"Watched: {n_of(len(watched), 'day')} with records, {hours:.1f} hours, {flows:,} flows")
    if sheet:
        by_time = len(rows) - matched
        say(f"From {os.path.basename(sheet)}: {n_of(matched, 'row')} matched to the alert log by id"
            + (f", {by_time} placed by their time (Excel may have changed their id)" if by_time else ""))
    if odd:
        say(f"Labels not understood, counted as not labelled: {dict(odd.most_common())}")

    say("\n| Day | Hours watched | Hours with traffic | Flows | Alerts | Test | False | Real | Not labelled |")
    say("|---|---|---|---|---|---|---|---|---|")
    for day in sorted({r["day"] for r in shown} | set(watched)):
        t = [r for r in shown if r["day"] == day]
        c = Counter(r["label"] for r in t)
        v = watched.get(day)
        active = f"{v['active_minutes'] / 60:.1f}" if v and isinstance(v.get("active_minutes"), (int, float)) else "?"
        cells = f"{v['minutes'] / 60:.1f} | {active} | {v.get('flows', 0):,}" if v else "? | ? | ?"
        say(f"| {day or 'unknown'} | {cells} | {len(t)} | {c['test']} | {c['false']} | {c['real']} | "
            f"{len(t) - sum(c[k] for k in LABELS)} |")

    false = [r for r in shown if r["label"] == "false" and r["day"] in watched]
    if hours:
        say(f"\nFalse alarms on the watched days: {len(false)} in {hours:.1f} hours = "
            f"{len(false) / hours * 24:.1f} per day")
        timed = {d: v for d, v in watched.items() if isinstance(v.get("active_minutes"), (int, float))}
        active = sum(v["active_minutes"] for v in timed.values()) / 60
        if active:
            n = sum(1 for r in false if r["day"] in timed)
            say(f"Hours with traffic: {active:.1f} of {sum(v['minutes'] for v in timed.values()) / 60:.1f} watched "
                f"on {n_of(len(timed), 'day')}: {n_of(n, 'false alarm')} = {n / active * 24:.1f} per 24 hours of use")
        quiet = {d: v.get("flows", 0) / (v["minutes"] / 60) for d, v in watched.items()
                 if v["minutes"] >= 60 and v.get("flows", 0) / (v["minutes"] / 60) < QUIET_FLOWS_PER_HOUR}
        if quiet:
            say("Hardly used, so not normal use yet: " + ", ".join(f"{d} ({f:.0f} flows an hour)"
                                                                  for d, f in sorted(quiet.items()))
                + ". A laptop in use makes thousands an hour.")
    else:
        say(f"\nNo watched time recorded yet ({show(days_path)}): leave the monitor running on the lab "
            "Wi-Fi for a day first.")
    all_false = [r for r in shown if r["label"] == "false"]
    if all_false:
        say(f"False alarms by kind: {dict(Counter(r['kind'] for r in all_false).most_common())}")
        say(f"False alarms by device: {dict(Counter(r['device_name'] or r['device'] for r in all_false).most_common())}")
    if hidden:
        say(f"\nNot counted: {n_of(len(hidden), 'alert')} on {n_of(len({r['day'] for r in hidden}), 'day')} "
            f"with no watched time in {show(days_path)} (older days, or the monitor was off). "
            "Add --all to list them.")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    paths = argparse.ArgumentParser(add_help=False)
    paths.add_argument("--alerts", default=ALERTS, help="the monitor's alerts")
    paths.add_argument("--tests", default=TESTS, help="the tests started from the Pi's page")
    paths.add_argument("--labels", default=LABELS_FILE, help="your answers from 'label'")
    paths.add_argument("--days", default=DAYS, help="watched time per day, kept by the monitor")
    lab = sub.add_parser("label", parents=[paths], help="say what each alert was, in the terminal")
    lab.add_argument("--all", action="store_true", help="also alerts of days without watched time")
    lab.add_argument("--again", action="store_true", help="also alerts that have a label already")
    m = sub.add_parser("measure", parents=[paths], help="false alarms per day")
    m.add_argument("sheet", nargs="?", help="a sheet from 'export' with its label column filled (optional)")
    m.add_argument("--all", action="store_true", help="also list days without watched time")
    e = sub.add_parser("export", parents=[paths], help="the alerts and their labels -> a sheet")
    e.add_argument("out")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "label":
            label(a.alerts, a.tests, a.labels, a.days, everything=a.all, again=a.again)
        elif a.cmd == "measure":
            measure(a.sheet, a.days, a.alerts, a.tests, a.labels, everything=a.all)
        else:
            export(a.alerts, a.tests, a.out, a.labels)
    except OSError as err:
        print(f"Can't use {err.filename or 'a file'}: {err.strerror}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

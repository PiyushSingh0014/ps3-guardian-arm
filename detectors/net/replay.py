"""Replay public IoT malware captures through the network monitor and report what fires (update 40).

    python -m detectors.net.replay ~/iot23/CTU-IoT-Malware-Capture-34-1 ~/iot23/CTU-Honeypot-Capture-4-1
    python -m detectors.net.replay --pcap ~/iot23/CTU-IoT-Malware-Capture-34-1    # the capture, through NFStream
    python -m detectors.net.replay ~/iot23/* --report ~/iot23/results.md
    python -m detectors.net.replay ~/iot23/* --learn-hours 0      # no learning time: what it hides

IoT-23 (Garcia, Parmisano and Erquiaga, Stratosphere Laboratory, 2020; CC BY 4.0,
doi:10.5281/zenodo.4743746): 20 captures of a Raspberry Pi infected with real IoT malware (Mirai,
Torii, Okiru, Hajime, Gagfyt and others) and 3 of real smart-home devices (a Philips Hue lamp, an
Amazon Echo and a Somfy door lock), each with its Zeek connection log labelled flow by flow
(bro/conn.log.labeled). scripts/get_iot23.sh downloads chosen ones.

Nothing is sent on any network: the flows are read from the files and fed to the same engine as the
live monitor (engine.py), with a fresh state, no watch list, no device names and no DNS blocking,
and the alerts go to this report, never to the app's alert list.

By default each line of the labelled Zeek log becomes a flow: addresses, ports, packets, payload
bytes, and the SYN and reset flags from Zeek's history string. That log names no websites, so the
checks on looked-up names (phishing sites, DGA names, DNS tunnels) need --pcap: NFStream then reads
the capture itself, as live, and the log is used only for its labels.

How it is scored, as for CIC-IDS2017 (eval_net.py):
  * each kind of malicious behaviour in the labels (PartOfAHorizontalPortScan, DDoS, C&C, Attack...) is
    detected if an alert names an address that showed it, between the 5th and 95th percentile of its
    flows in time, give or take 5 minutes; "fitting" if the alert is of a kind that matches the
    behaviour (a scan for a scan, a flood for a DDoS, a beacon or a risky port for C&C);
  * on the three benign captures every alert is a false alarm; on the malware captures an alert that
    names no address with malicious flows is one too. Alerts about an infected address outside its
    labelled periods are counted apart.
"""
import argparse
import glob
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.net.flows import FlowRec, is_private          # noqa: E402

GRACE_MS = 5 * 60_000
ZEEK_FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes "
               "conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts "
               "resp_ip_bytes tunnel_parents label detailed-label").split()
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
SERVICE = {"dns": "DNS", "http": "HTTP", "ssl": "TLS", "irc": "IRC", "ssh": "SSH", "dhcp": "DHCP", "ntp": "NTP"}
# What fits each word in IoT-23's detailed labels (a label such as "C&C-HeartBeat-FileDownload"
# fits any alert kind of any of its words).
FITS = {"PortScan": {"network_scan", "port_scan"}, "DDoS": {"dos_flood"},
        "C&C": {"malware_beacon", "risky_port", "dga_domains"}, "HeartBeat": {"malware_beacon", "risky_port"},
        "Attack": {"brute_force", "network_scan", "port_scan", "risky_port", "dos_flood"},
        "Okiru": {"network_scan", "port_scan"}, "Mirai": {"network_scan", "risky_port", "malware_beacon"},
        "Torii": {"malware_beacon", "risky_port"}, "FileDownload": {"device_anomaly"}}
# Other names for the last column: CTU-IoT-Malware-Capture-34-1's header calls it "det_label".
FIELD_ALIASES = {"det_label": "detailed-label", "detailed_label": "detailed-label", "detailedlabel": "detailed-label"}
PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}
MAX_REMOTE = 10_000                   # internet addresses counted per behaviour (scans reach millions)


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def zeek_rows(path):
    """Rows of a Zeek conn.log (or IoT-23's conn.log.labeled) as dicts. In most IoT-23 files the last
    three columns (tunnel_parents, label, detailed-label) are separated by spaces, not tabs, and
    some headers name the last one differently (FIELD_ALIASES). No Zeek conn field holds a space,
    so a last part with spaces in it is always several columns."""
    fields = list(ZEEK_FIELDS)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = [FIELD_ALIASES.get(n, n) for n in line.split()[1:]]
                continue
            parts = line.split("\t")
            while len(parts) > 1 and parts[-1] == "":                  # a stray tab at the end
                parts.pop()
            if len(parts[-1].split()) > 1:
                parts = parts[:-1] + parts[-1].split()
            if len(parts) == len(fields) + 2 and "label" not in fields:      # labels after a plain Zeek header
                fields = fields + ["label", "detailed-label"]
            yield dict(zip(fields, parts))


def flow_from_zeek(row):
    """One Zeek conn.log row -> FlowRec (None if unusable). label is "Benign" or the detailed label."""
    try:
        ts = float(row["ts"])
    except (KeyError, ValueError):
        return None
    dur = row.get("duration", "-")
    end = ts + (float(dur) if dur not in ("-", "", None) else 0.0)
    hist = row.get("history", "-") or "-"
    label = row.get("label", "") or ""
    detail = row.get("detailed-label", "-") or "-"
    if label.lower() == "malicious":
        label = detail if detail != "-" else "Malicious"
    elif label.lower() == "benign":
        label = "Benign"
    return FlowRec(start_ms=int(ts * 1000), end_ms=int(end * 1000), src=row.get("id.orig_h", ""),
                   dst=row.get("id.resp_h", ""), sport=_int(row.get("id.orig_p")), dport=_int(row.get("id.resp_p")),
                   proto=PROTO.get(row.get("proto", ""), 0), pkts_out=_int(row.get("orig_pkts")),
                   pkts_in=_int(row.get("resp_pkts")), bytes_out=_int(row.get("orig_bytes")),
                   bytes_in=_int(row.get("resp_bytes")), syn_out=1 if "S" in hist else 0,
                   rst_in=1 if "r" in hist else 0, app=SERVICE.get(row.get("service", ""), ""), label=label)


def read_zeek(path):
    for row in zeek_rows(path):
        r = flow_from_zeek(row)
        if r is not None:
            yield r


def behaviours(flows, counts=None):
    """Malicious label -> its addresses (the private ones that showed it), flow count, main period
    and what its traffic looks like (main port, internet addresses, share unanswered, how often).
    One pass, little memory: some IoT-23 logs hold tens of millions of flows. counts: a Counter
    that gets the number of benign and malicious flows."""
    from array import array
    out = {}
    for r in flows:
        if counts is not None:
            counts["benign" if r.label == "Benign" else "malicious" if r.label else "unlabelled"] += 1
        if not r.label or r.label == "Benign":
            continue
        b = out.setdefault(r.label, {"addrs": set(), "starts": array("q"), "flows": 0, "ports": Counter(),
                                     "remote": set(), "unanswered": 0})
        b["addrs"].update(a for a in (r.src, r.dst) if is_private(a))
        b["starts"].append(r.start_ms)
        b["flows"] += 1
        b["ports"][(r.dport, r.proto)] += 1
        if len(b["remote"]) < MAX_REMOTE:
            b["remote"].update(a for a in (r.src, r.dst) if a and not is_private(a))
        b["unanswered"] += not r.answered
    for b in out.values():
        starts = b.pop("starts")
        try:
            import numpy as np
            t = np.sort(np.frombuffer(starts, dtype=np.int64))
            pick = lambda q: int(t[int(q * (len(t) - 1))])          # noqa: E731
        except ImportError:
            t = sorted(starts)
            pick = lambda q: t[int(q * (len(t) - 1))]               # noqa: E731
        b["first_flow"], b["first"], b["last"] = pick(0.0), pick(0.05), pick(0.95)
        n = b["flows"]
        b["every_s"] = (pick(1.0) - pick(0.0)) / 1000 / (n - 1) if n > 1 else None
        (port, proto), k = b.pop("ports").most_common(1)[0]
        b["port"], b["port_share"] = f"{port}/{PROTO_NAME.get(proto, proto)}", k / n
        b["remote"] = len(b["remote"])
    return out


def fits(label, category):
    """Does an alert of this kind fit the label? None when the label names no behaviour ("Malicious")."""
    words = [w for w in FITS if w in label]
    if not words:
        return None
    return any(category in FITS[w] for w in words)


def _every(seconds):
    if seconds is None:
        return "once"
    if seconds < 1:
        return f"{1 / seconds:.0f} a second" if seconds > 0 else "all at once"
    if seconds < 90:
        return f"every {seconds:.0f} s"
    return f"every {seconds / 60:.0f} min" if seconds < 5400 else f"every {seconds / 3600:.1f} h"


def traffic(b):
    """What a behaviour's flows look like, in one line."""
    remote = f"{b['remote']:,}{'+' if b['remote'] >= MAX_REMOTE else ''}"
    return (f"port {b['port']} ({b['port_share']:.0%}), {remote} internet address"
            f"{'' if b['remote'] == 1 else 'es'}, {b['unanswered'] / b['flows']:.0%} unanswered, {_every(b['every_s'])}")


def score(alerts, labels):
    """Detection per behaviour and the false alarms, from the alerts and the labelled behaviours."""
    infected = set().union(*(b["addrs"] for b in labels.values())) if labels else set()
    rows = []
    for lab, b in sorted(labels.items(), key=lambda kv: kv[1]["first_flow"]):
        hit = [f for f in alerts if f.entities.get("device") in b["addrs"]
               and b["first"] - GRACE_MS <= f.entities.get("time_ms", 0) <= b["last"] + GRACE_MS]
        known = fits(lab, "") is not None
        good = [f for f in hit if fits(lab, f.category)]
        first = min((f.entities["time_ms"] for f in (good or hit)), default=None)
        rows.append({"label": lab, "flows": b["flows"], "detected": bool(hit), "fitting": bool(good) if known else None,
                     "kinds": Counter(f.category for f in hit), "traffic": traffic(b) if "port" in b else "",
                     "after_s": None if first is None else max(0, round((first - b["first_flow"]) / 1000))})
    in_any = [f for f in alerts if any(f.entities.get("device") in b["addrs"] and
                                       b["first"] - GRACE_MS <= f.entities.get("time_ms", 0) <= b["last"] + GRACE_MS
                                       for b in labels.values())]
    false = [f for f in alerts if f.entities.get("device") not in infected]
    outside = [f for f in alerts if f not in in_any and f not in false]
    return rows, false, outside


def scenarios(folder):
    """[(name, labelled log, capture file or None)] in a folder: one per labelled log. Most IoT-23
    folders hold one; the Somfy door lock's (CTU-Honeypot-Capture-7-1) holds six, Somfy-01 to Somfy-06."""
    folder = os.path.normpath(folder)
    logs = sorted(glob.glob(os.path.join(folder, "**", "conn.log.labeled"), recursive=True)) or \
        sorted(glob.glob(os.path.join(folder, "**", "conn.log"), recursive=True))
    out = []
    for log in logs:
        d = os.path.dirname(log)
        if os.path.basename(d) == "bro":
            d = os.path.dirname(d)
        name = os.path.relpath(d, os.path.dirname(folder)).replace(os.sep, "/")
        pcaps = sorted(glob.glob(os.path.join(d, "*.pcap")) + glob.glob(os.path.join(d, "*.pcapng")))
        out.append((name, log, pcaps[0] if pcaps else None))
    return out


def find_files(folder):
    """(labelled conn log, capture file or None): the first capture in an IoT-23 scenario folder."""
    found = scenarios(folder)
    return (found[0][1], found[0][2]) if found else (None, None)


def replay(folder, use_pcap=False, learn_hours=2.0, engine=None, say=print):
    """Replay the (first) capture in one scenario folder; returns a dict for the report."""
    found = scenarios(folder)
    if not found:
        raise FileNotFoundError(f"{folder}: no conn.log.labeled (bash scripts/get_iot23.sh downloads it)")
    return replay_log(*found[0], use_pcap=use_pcap, learn_hours=learn_hours, engine=engine, say=say)


def _result(row, long=False):
    if not row["detected"]:
        return "missed"
    note = {True: "", False: " (not the fitting kind)" if long else " (other kind)",
            None: " (the label names no kind)"}[row["fitting"]]
    return f"detected after {row['after_s']} s{note}" if long else f"detected{note}, after {row['after_s']} s"


def replay_log(name, log, pcap=None, use_pcap=False, learn_hours=2.0, engine=None, say=print):
    """Replay one labelled log (or its capture, with use_pcap) through a fresh engine."""
    from detectors.net.engine import NetEngine
    if use_pcap and pcap is None:
        raise FileNotFoundError(f"{name}: no .pcap file (bash scripts/get_iot23.sh --pcap ...)")
    counts = Counter()
    labels = behaviours(read_zeek(log), counts)           # first pass: the labels only
    if engine is None:
        engine = NetEngine(learn_ms=int(learn_hours * 3600_000), leases=None, state_path=None,
                           url_detector="auto" if use_pcap else None, dga_model="auto" if use_pcap else None)
    if use_pcap:
        from detectors.net.flows import read_flows
        flows = read_flows(pcap)
    else:
        flows = read_zeek(log)                            # second pass: the flows, one at a time
    alerts, n, t0, t1 = [], 0, None, None
    for r in flows:
        n += 1
        t0 = r.start_ms if t0 is None else min(t0, r.start_ms)
        t1 = r.end_ms if t1 is None else max(t1, r.end_ms)
        alerts += engine.feed(r)
    rows, false, outside = score(alerts, labels)
    hours = (t1 - t0) / 3_600_000 if n else 0.0
    say(f"\n{name}: {n:,} flows ({counts['malicious']:,} labelled malicious) over {hours:.1f} h "
        f"({'capture, NFStream' if use_pcap else 'Zeek log'}), {len(alerts)} alerts")
    for row in rows:
        kinds = ", ".join(f"{k} {v}" for k, v in row["kinds"].most_common(3)) or "none"
        say(f"  {row['label']:40s} {row['flows']:9,} flows  {_result(row, long=True)}  [{kinds}]")
        if row["traffic"]:
            say(f"      {row['traffic']}")
    say(f"  false alarms: {len(false)} ({len(false) / hours:.2f} an hour)" if hours else f"  false alarms: {len(false)}")
    if false:
        say("    " + ", ".join(f"{k} {v}" for k, v in Counter(f.category for f in false).most_common(5)))
    if outside:
        say(f"  alerts about an infected address outside its labelled periods: {len(outside)}")
    return {"name": name, "flows": n, "malicious_flows": counts["malicious"], "hours": hours, "alerts": len(alerts),
            "rows": rows, "false": len(false), "false_kinds": Counter(f.category for f in false),
            "outside": len(outside), "mode": "capture" if use_pcap else "zeek", "benign": not labels,
            "learn_hours": learn_hours}


def report_md(results):
    """A Markdown summary for eval/results_net.md."""
    lines = ["| Capture | Flows | Hours | Behaviour (IoT-23 label) | Labelled flows | Result | Alert kinds | Its traffic |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for res in results:
        head = f"| {res['name']} | {res['flows']:,} | {res['hours']:.1f} |"
        false_kinds = ", ".join(f"{k} {v}" for k, v in res["false_kinds"].most_common(3)) or "–"
        if not res["rows"]:
            lines.append(f"{head} benign | – | {res['false']} false alarms | {false_kinds} | |")
            continue
        for i, row in enumerate(res["rows"]):
            kinds = ", ".join(f"{k} {v}" for k, v in row["kinds"].most_common(3)) or "–"
            lines.append((head if i == 0 else "| | | |")
                         + f" {row['label']} | {row['flows']:,} | {_result(row)} | {kinds} | {row['traffic']} |")
        lines.append(f"| | | | false alarms | – | {res['false']} | {false_kinds} | |")
    return "\n".join(lines) + "\n"


def summary(results):
    """Totals over all captures, as lines."""
    benign = [r for r in results if r["benign"]]
    malware = [r for r in results if not r["benign"]]
    out = []
    if benign:
        hours, false = sum(r["hours"] for r in benign), sum(r["false"] for r in benign)
        out.append(f"smart-home captures: {len(benign)}, {hours:.1f} h, {false} false alarms"
                   + (f" ({false / hours:.2f} an hour)" if hours else ""))
    if malware:
        rows = [row for r in malware for row in r["rows"]]
        out.append(f"malware captures: {len(malware)}; labelled behaviours detected: "
                   f"{sum(row['detected'] for row in rows)} of {len(rows)} "
                   f"({sum(row['fitting'] is True for row in rows)} by the fitting kind); "
                   f"false alarms: {sum(r['false'] for r in malware)}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("folders", nargs="+", help="IoT-23 scenario folders (with bro/conn.log.labeled)")
    ap.add_argument("--pcap", action="store_true", help="read each capture through NFStream, as live")
    ap.add_argument("--learn-hours", type=float, default=2.0, help="learning time per device (as live: 2)")
    ap.add_argument("--report", help="also write a Markdown table here")
    a = ap.parse_args(argv)
    results = []
    for folder in a.folders:
        if not os.path.isdir(folder):                    # e.g. a report written into ~/iot23
            continue
        found = scenarios(folder)
        if not found:
            print(f"skipped: {folder}: no conn.log.labeled (bash scripts/get_iot23.sh downloads it)")
        for name, log, pcap in found:
            try:
                results.append(replay_log(name, log, pcap, a.pcap, a.learn_hours))
            except FileNotFoundError as e:
                print(f"skipped: {e}")
    if results:
        print(f"\nSummary (learning time {a.learn_hours:g} h per device):")
        for line in summary(results):
            print("  " + line)
    if a.report and results:
        with open(a.report, "w", encoding="utf-8") as f:
            f.write(report_md(results))
        print(f"\nwrote {a.report}")
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())

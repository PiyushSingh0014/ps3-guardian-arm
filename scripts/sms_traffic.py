"""Measure the detector on real SMS traffic forwarded by the Android companion.

1. Export the log the Pi keeps (logs/sms_traffic.jsonl) to a sheet:
       python scripts/sms_traffic.py export traffic.csv
2. Open traffic.csv in Excel and fill the 'label' column: smishing (fraud),
   spam (genuine marketing) or ham (normal). Leave a row empty if unsure.
3. Measure: flagged messages per label, text only vs with the sender ID:
       python scripts/sms_traffic.py measure traffic.csv

The log already holds both verdicts (the app's, with the sender, and the text-only one),
so nothing is re-scored. Texts in the log have every digit replaced by '#', and texts
from phone numbers that were judged safe are not stored (see app/sms_log.py).
"""
import argparse
import csv
import json
import sys
from collections import Counter

COLUMNS = ["id", "time", "sender", "sender_kind", "verdict", "score", "text_verdict", "text_score",
           "category", "text", "label", "notes"]
LABELS = {"smishing": "fraud", "spam": "marketing", "ham": "normal"}


def export(log_path, out_path):
    rows = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                rows.append({k: e.get(k, "") if e.get(k) is not None else "" for k in COLUMNS})
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel reads Hindi correctly
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} messages to {out_path}. Fill the 'label' column, then run 'measure'.")


def measure(path):
    with open(path, encoding="utf-8-sig") as f:
        rows = [r for r in csv.DictReader(f)]
    labelled = [r for r in rows if r.get("label", "").strip().lower() in LABELS]
    print(f"{len(rows)} messages, {len(labelled)} labelled")
    print("Senders:", ", ".join(f"{k} {n}" for k, n in Counter(r['sender_kind'] for r in labelled).items()))
    print(f"\n{'label':10s} {'messages':>8s} {'flagged, text only':>19s} {'flagged, with sender':>21s}")
    for lab, name in LABELS.items():
        t = [r for r in labelled if r["label"].strip().lower() == lab]
        if t:
            f1 = sum(r["text_verdict"] != "safe" for r in t)
            f2 = sum(r["verdict"] != "safe" for r in t)
            print(f"{name:10s} {len(t):8d} {f1:12d} ({f1 / len(t):4.0%}) {f2:14d} ({f2 / len(t):4.0%})")
    wrong = [r for r in labelled if (r["label"].strip().lower() == "ham") == (r["verdict"] != "safe")
             and r["label"].strip().lower() != "spam"]
    if wrong:
        print("\nWrong with sender (normal flagged, or fraud missed):")
        for r in wrong[:20]:
            print(f"  {r['label']:8s} {r['verdict']:10s} {r['sender']:14s} {(r['text'] or '(text not stored)')[:80]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("out")
    e.add_argument("--log", default="logs/sms_traffic.jsonl")
    m = sub.add_parser("measure")
    m.add_argument("sheet")
    a = ap.parse_args()
    if a.cmd == "export":
        export(a.log, a.out)
    else:
        measure(a.sheet)


if __name__ == "__main__":
    sys.exit(main())

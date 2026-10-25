"""Measure the detector on real traffic forwarded by the Android companion (SMS and chats).

1. Export the log the Pi keeps (logs/sms_traffic.jsonl) to a sheet:
       python scripts/sms_traffic.py export traffic.csv
2. Open traffic.csv in Excel and fill the 'label' column: smishing (fraud),
   spam (genuine marketing) or ham (normal). Leave a row empty if unsure.
   With several phones, each person labels the rows of their phone ('device' column):
   for a row without text (a safe personal message), find it on the phone by its time.
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

COLUMNS = ["id", "time", "device", "channel", "app", "sender", "sender_kind", "verdict", "score",
           "text_verdict", "text_score", "category", "text", "label", "notes"]
LABELS = {"smishing": "fraud", "spam": "marketing", "ham": "normal"}


def export(log_path, out_path):
    rows = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                e["channel"] = e.get("channel") or "sms"         # lines written before chats were added
                rows.append({k: e.get(k, "") if e.get(k) is not None else "" for k in COLUMNS})
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel reads Hindi correctly
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} messages to {out_path}. Fill the 'label' column, then run 'measure'.")


def label_of(r):
    return (r.get("label") or "").strip().lower()


def table(rows, title):
    print(f"\n{title}")
    print(f"{'label':10s} {'messages':>8s} {'flagged, text only':>19s} {'flagged, with sender':>21s}")
    for lab, name in LABELS.items():
        t = [r for r in rows if label_of(r) == lab]
        if t:
            f1 = sum(r["text_verdict"] != "safe" for r in t)
            f2 = sum(r["verdict"] != "safe" for r in t)
            print(f"{name:10s} {len(t):8d} {f1:12d} ({f1 / len(t):4.0%}) {f2:14d} ({f2 / len(t):4.0%})")


def measure(path):
    with open(path, encoding="utf-8-sig") as f:
        rows = [r for r in csv.DictReader(f)]
    labelled = [r for r in rows if label_of(r) in LABELS]
    print(f"{len(rows)} messages, {len(labelled)} labelled")
    print("Senders:", ", ".join(f"{k} {n}" for k, n in Counter(r['sender_kind'] for r in labelled).items()))
    phones = Counter((r.get("device") or "-") for r in labelled)
    if set(phones) != {"-"}:
        print("Phones:", ", ".join(f"{k} {n}" for k, n in sorted(phones.items())))
    table(labelled, "All messages")
    channels = sorted({(r.get("channel") or "sms") for r in labelled})
    if len(channels) > 1:
        for ch in channels:
            table([r for r in labelled if (r.get("channel") or "sms") == ch], f"{ch.upper()} only")
    wrong = [r for r in labelled if (label_of(r) == "ham") == (r["verdict"] != "safe") and label_of(r) != "spam"]
    if wrong:
        print("\nWrong with sender (normal flagged, or fraud missed):")
        for r in wrong[:20]:
            where = f"{r.get('device') or '-'}/{r.get('channel') or 'sms'}"
            print(f"  {label_of(r):8s} {r['verdict']:10s} {where:10s} {r['sender']:14s} "
                  f"{(r['text'] or '(text not stored)')[:70]}")


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

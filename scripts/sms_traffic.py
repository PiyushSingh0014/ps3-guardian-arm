"""Label and measure the real traffic forwarded by the Android companion (SMS and chats).

1. Label, in the Pi's terminal. Each person labels the messages of their own phone:
       python scripts/sms_traffic.py label --device C
   f = fraud, m = genuine marketing, n = normal, Enter = not sure (skip), u = undo, q = stop.
   Identical messages (an OTP text from the same bank, digits aside) are asked once. Labels are
   saved at once in data/sms/labels.json; run it again to carry on where you stopped.
2. Measure: flagged messages per label, text only vs with the sender ID, as the app decided:
       python scripts/sms_traffic.py measure
3. Train and compare SMS model v2: python detectors/sms/train_v2.py (docs/sms-model-v2.md).

Labelling in Excel still works: `export traffic.csv`, fill the 'label' column (smishing, spam or
ham), then `import traffic.csv` (into data/sms/labels.json, which SMS model v2 reads) or just
`measure traffic.csv`.

The log already holds both verdicts (the app's, with the sender, and the text-only one), so
nothing is re-scored here. Texts in the log have every digit replaced by '#', and texts from
phone numbers that were judged safe are not stored (see app/sms_log.py).
"""
import argparse
import csv
import json
import os
import re
import sys
import textwrap
from collections import Counter

COLUMNS = ["id", "time", "device", "channel", "app", "sender", "sender_kind", "verdict", "score",
           "text_verdict", "text_score", "category", "text", "label", "notes"]
LABELS = {"smishing": "fraud", "spam": "marketing", "ham": "normal"}
KEYS = {"f": "smishing", "m": "spam", "n": "ham"}
DEFAULT_LOG = "logs/sms_traffic.jsonl"
DEFAULT_LABELS = "data/sms/labels.json"


def read_log(path):
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    for e in rows:
        e["channel"] = e.get("channel") or "sms"          # lines written before chats were added
    return rows


def load_labels(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_labels(path, labels):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=0, sort_keys=True)
    os.replace(tmp, path)


def export(log_path, out_path, labels_path=DEFAULT_LABELS):
    labels = load_labels(labels_path)
    rows = []
    for e in read_log(log_path):
        row = {k: e.get(k, "") if e.get(k) is not None else "" for k in COLUMNS}
        row["label"] = labels.get(e.get("id"), "")
        rows.append(row)
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel reads Hindi correctly
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} messages to {out_path}. Fill the 'label' column, then run 'measure'.")


def import_labels(sheet, labels_path, say=print):
    """The 'label' column of a sheet from 'export' into the labels file, by message id."""
    labels = load_labels(labels_path)
    with open(sheet, encoding="utf-8-sig") as f:
        rows = [r for r in csv.DictReader(f) if r.get("id") and label_of(r) in LABELS]
    for r in rows:
        labels[r["id"]] = label_of(r)
    save_labels(labels_path, labels)
    say(f"Imported {len(rows)} labels into {labels_path} ({len(labels)} labelled in all).")
    return 0


def same_message(e):
    """Messages asked once: the same text (digits aside) from the same sender on the same phone."""
    text = " ".join(re.sub(r"[\d#]", "#", e.get("text") or "").lower().split())
    return text, e.get("sender") or "", e.get("device") or ""


def label(log_path, labels_path, device=None, again=False, ask=input, say=print):
    entries = [e for e in read_log(log_path) if e.get("text")]
    if device is not None:
        names = sorted({e.get("device") or "-" for e in entries})
        entries = [e for e in entries if (e.get("device") or "") == device]
        if not entries:
            say(f"No messages with text from phone {device}. Phones in the log: {', '.join(names) or 'none'} "
                "(the names are case-sensitive).")
            return 1
    groups = {}
    for e in entries:
        groups.setdefault(same_message(e), []).append(e)
    labels = load_labels(labels_path)
    todo = [g for g in groups.values() if again or any(e["id"] not in labels for e in g)]
    phones = sorted({(e.get("device") or "-") for e in entries})
    if not todo:
        say(f"Nothing left to label{' on phone ' + device if device else ''} "
            f"({len(entries)} messages with text). --again labels them again.")
        return 0
    say(f"{len(todo)} messages to label ({sum(len(g) for g in todo)} with their copies), phones: {', '.join(phones)}.")
    say("f = fraud, m = genuine marketing, n = normal, Enter = not sure, u = undo, q = stop. Saved at once.\n")
    done, i = [], 0
    while i < len(todo):
        g, e = todo[i], todo[i][0]
        where = e["channel"].upper() + (f" ({e['app']})" if e.get("app") else "")
        app_said = f"{e.get('verdict', '?').upper()} {e.get('score', '')}"
        alone = f"{e.get('text_verdict', '?').upper()} {e.get('text_score', '')}"
        copies = f" · {len(g)} copies" if len(g) > 1 else ""
        say(f"[{i + 1}/{len(todo)}] phone {e.get('device') or '-'} · {where} · {e.get('time', '')} · from "
            f"{e.get('sender') or '?'} · app: {app_said} (text alone: {alone}){copies}")
        for line in textwrap.wrap(e["text"], 100) or [""]:
            say("    " + line)
        try:
            answer = ask("label: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            say("")
            break
        if answer == "q":
            break
        if answer == "u":
            if done:
                i = done.pop()
                for x in todo[i]:
                    labels.pop(x["id"], None)
                save_labels(labels_path, labels)
            continue
        if answer in KEYS:
            for x in g:
                labels[x["id"]] = KEYS[answer]
            save_labels(labels_path, labels)
            done.append(i)
        elif answer:
            say("    (f, m, n, Enter, u or q)")
            continue
        i += 1
    mine = Counter(LABELS[labels[e["id"]]] for e in entries if e["id"] in labels)
    left = sum(1 for e in entries if e["id"] not in labels)
    say(f"\nLabelled{' on phone ' + device if device else ''}: " + ", ".join(f"{k} {n}" for k, n in mine.items())
        + f"; {left} messages not labelled.")
    return 0


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


def measure_rows(rows):
    labelled = [r for r in rows if label_of(r) in LABELS]
    no_text = sum(1 for r in rows if not r.get("text"))
    print(f"{len(rows)} messages, {len(labelled)} labelled; {no_text} without text "
          "(safe messages from phone numbers: the text is not kept)")
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


def measure(path):
    with open(path, encoding="utf-8-sig") as f:
        measure_rows([r for r in csv.DictReader(f)])


def measure_log(log_path, labels_path):
    labels = load_labels(labels_path)
    rows = []
    for e in read_log(log_path):
        r = {k: "" if e.get(k) is None else e.get(k) for k in COLUMNS}
        r["label"] = labels.get(e.get("id"), "")
        rows.append(r)
    measure_rows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("out")
    lb = sub.add_parser("label")
    lb.add_argument("--device", help="only this phone's messages (the name typed in its app, e.g. C)")
    lb.add_argument("--again", action="store_true", help="also show messages labelled before")
    m = sub.add_parser("measure")
    m.add_argument("sheet", nargs="?", help="a labelled CSV from 'export'; without it, the labels from 'label'")
    im = sub.add_parser("import")
    im.add_argument("sheet", help="a CSV from 'export' with the 'label' column filled")
    for p in (e, lb, m, im):
        p.add_argument("--log", default=DEFAULT_LOG)
        p.add_argument("--labels", default=DEFAULT_LABELS)
    a = ap.parse_args(argv)
    if a.cmd == "export":
        export(a.log, a.out, a.labels)
    elif a.cmd == "label":
        return label(a.log, a.labels, a.device, a.again)
    elif a.cmd == "import":
        return import_labels(a.sheet, a.labels)
    elif a.sheet:
        measure(a.sheet)
    else:
        measure_log(a.log, a.labels)
    return 0


if __name__ == "__main__":
    sys.exit(main())

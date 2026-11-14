"""Label and measure the real traffic forwarded by the Android companion (SMS and chats).

1. Label, in the Pi's terminal. Each person labels the messages of their own phone:
       python scripts/sms_traffic.py label --device C
   f = fraud, m = genuine marketing, n = normal, Enter = not sure (skip), u = undo, q = stop.
   Identical messages (an OTP text from the same bank, digits aside) are asked once. Labels are
   saved at once in data/sms/labels.json; run it again to carry on where you stopped.
   Only the flagged messages, to count false alarms quickly: label --flagged
   A second look at labels that are likely wrong (the same message labelled two ways, fraud
   from a registered sender ID): python scripts/sms_traffic.py review
2. Measure: every message received by kind of sender, and flagged messages per label, text only
   vs with the sender ID, as the app decided:
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

COLUMNS = ["id", "time", "device", "study", "channel", "app", "sender", "sender_kind", "verdict", "score",
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


RULES = """How to label: judge the message itself (the app's verdict is not shown).
  f  fraud: it tries to trick you. A fake bank, KYC, parcel, prize, refund, job or loan message,
     a link or number to a fake site or person, or it asks for money, an OTP, a PIN or your details.
  m  marketing: a real business advertising: offers, sales, plans, cashback, even your own bank's.
  n  normal: anything else that is real: OTPs, bank alerts, bills, bookings, deliveries, chats.
     An OTP you did not ask for is still n: the message is real (someone may be trying your number).
  u  undo the last answer     q  stop (every answer is saved at once)"""


def phone_of(e):
    return e.get("device") or "-"


def same_message(e):
    """Messages asked once: the same text (digits aside) from the same sender on the same phone."""
    text = " ".join(re.sub(r"[\d#]", "#", e.get("text") or "").lower().split())
    return text, e.get("sender") or "", e.get("device") or ""


def show(e, say, before="", after=""):
    """One message to label: where it came from and its text, never the app's verdict."""
    where = e["channel"].upper() + (f" ({e['app']})" if e.get("app") else "")
    say(f"{before}phone {phone_of(e)} · {where} · {e.get('time', '')} · from {e.get('sender') or '?'}{after}")
    for line in textwrap.wrap(e["text"], 100) or [""]:
        say("    " + line)


def ask_loop(todo, labels, labels_path, ask, say, header):
    """Asks each group of copies once (todo: [(entries, note)]). Enter changes nothing; u undoes the
    last answer, putting back the label it replaced."""
    done, i = [], 0
    while i < len(todo):
        group, note = todo[i]
        header(i, group, note)
        try:
            answer = ask("label: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            say("")
            break
        if answer == "q":
            break
        if answer == "u":
            if done:
                i, before = done.pop()
                for e in todo[i][0]:
                    if before[e["id"]] is None:
                        labels.pop(e["id"], None)
                    else:
                        labels[e["id"]] = before[e["id"]]
                save_labels(labels_path, labels)
            continue
        if answer in KEYS:
            done.append((i, {e["id"]: labels.get(e["id"]) for e in group}))
            for e in group:
                labels[e["id"]] = KEYS[answer]
            save_labels(labels_path, labels)
        elif answer:
            say("    (f, m, n, Enter, u or q)")
            continue
        i += 1


def label(log_path, labels_path, device=None, again=False, ask=input, say=print, flagged=False):
    """flagged: only the messages the app flagged, each a true alert or a false alarm."""
    entries = [e for e in read_log(log_path) if e.get("text") and not (flagged and e.get("verdict") == "safe")]
    labels = load_labels(labels_path)
    left = Counter(phone_of(e) for e in entries if again or e["id"] not in labels)
    if device is not None:
        if not any(phone_of(e) == device for e in entries):
            names = sorted({phone_of(e) for e in entries})
            say(f"No messages with text from phone {device}. Phones in the log: {', '.join(names) or 'none'} "
                "(the names are case-sensitive; - is a phone without a name).")
            return 1
        entries = [e for e in entries if phone_of(e) == device]
    groups = {}
    for e in entries:
        groups.setdefault(same_message(e), []).append(e)
    todo = [(g, "") for g in groups.values() if again or any(e["id"] not in labels for e in g)]
    if not todo:
        say(f"Nothing left to label{' on phone ' + device if device else ''} "
            f"({len(entries)} messages with text). --again labels them again.")
        return 0
    say(f"{'Flagged messages' if flagged else 'Messages'} left to label, by phone: "
        + ", ".join(f"{p} {n}" for p, n in sorted(left.items())))
    say(f"Now: {len(todo)} messages to label ({sum(len(g) for g, _ in todo)} with their copies).\n")
    say(RULES + "\n  Enter: not sure (skipped)\n")

    def header(i, group, note):
        show(group[0], say, f"[{i + 1}/{len(todo)}] ", f" · {len(group)} copies" if len(group) > 1 else "")

    ask_loop(todo, labels, labels_path, ask, say, header)
    mine = Counter(LABELS[labels[e["id"]]] for e in entries if e["id"] in labels)
    rest = sum(1 for e in entries if e["id"] not in labels)
    say(f"\nLabelled{' on phone ' + device if device else ''}: " + ", ".join(f"{k} {n}" for k, n in mine.items())
        + f"; {rest} messages not labelled.")
    return 0


def review(log_path, labels_path, ask=input, say=print):
    """A second look at labels that are likely wrong: the same message labelled two ways (on one
    phone or on two), and fraud from a registered sender ID, which belongs to a real business.
    Asked without the app's verdict; Enter keeps the label as it is."""
    labels = load_labels(labels_path)
    groups = {}
    for e in read_log(log_path):
        if e.get("text") and e.get("id") in labels:
            groups.setdefault(same_message(e)[0], []).append(e)
    todo = []
    for g in groups.values():
        kinds = {labels[e["id"]] for e in g}
        if len(kinds) > 1:
            todo.append((g, "labelled two ways: " + " and ".join(sorted(LABELS[k] for k in kinds))))
        elif kinds == {"smishing"} and any(e.get("sender_kind") == "business" for e in g):
            todo.append((g, "labelled fraud, but it came from a registered sender ID"))
    if not todo:
        say("Nothing to review: no message is labelled two ways, and none from a registered sender ID is "
            "labelled fraud.")
        return 0
    say(f"{len(todo)} labels to look at again ({sum(len(g) for g, _ in todo)} with their copies).")
    say("A registered sender ID (like VK-SBIBNK-P) belongs to a real business: its offers are m, its OTPs "
        "and alerts n.\nKeep f only if the message itself tries to trick you.\n")
    say(RULES + "\n  Enter: keep the label as it is\n")

    def header(i, group, note):
        others = sorted({phone_of(e) for e in group[1:]} | {e.get("sender") or "?" for e in group[1:]})
        show(group[0], say, f"[{i + 1}/{len(todo)}] ", f" · {len(group)} copies" if len(group) > 1 else "")
        say(f"    -> {note}" + (f" (copies also: {', '.join(others)})" if others else ""))

    ask_loop(todo, labels, labels_path, ask, say, header)
    say("\nDone. Run measure and train_v2.py again.")
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


# Who sent a message decides whether the log keeps its text (app/sms_log.py): always for SMS from
# a registered sender ID or another sender name, only when flagged for phone numbers and chats.
GROUPS = (("SMS from a registered sender ID", "sms", ("business",), True),
          ("SMS from another name or short code", "sms", ("other",), True),
          ("SMS from a phone number", "sms", ("mobile",), False),
          ("SMS without a sender", "sms", ("unknown", ""), False),
          ("Chat from an unknown number", "chat", ("mobile",), False),
          ("Chat from a saved contact (testing switch)", "chat", ("name",), False),
          ("Chat without a sender", "chat", ("unknown", ""), False))


def received_table(rows):
    """Every message received, labelled or not: false alarms per 100 messages need them all."""
    print("\nEvery message received, as the app decided:")
    print(f"{'':44s} {'':>8s} {'':>8s}  {'flagged and labelled':^24s} {'not':>8s} {'missed':>7s} {'normal flagged':>15s}")
    print(f"{'sender':44s} {'received':>8s} {'flagged':>8s}  {'fraud':>6s} {'mkt':>6s} {'normal':>8s}  {'labelled':>8s} {'scams':>7s} {'per 100 msgs':>15s}")
    total = Counter()
    for name, channel, kinds, kept in GROUPS:
        t = [r for r in rows if (r.get("channel") or "sms") == channel and (r.get("sender_kind") or "") in kinds]
        if not t:
            continue
        flagged = [r for r in t if r.get("verdict") != "safe"]
        c = Counter(label_of(r) for r in flagged)
        todo = sum(1 for r in t if r.get("text") and label_of(r) not in LABELS)
        missed = sum(1 for r in t if r.get("verdict") == "safe" and label_of(r) == "smishing")
        total.update(received=len(t), flagged=len(flagged), fraud=c["smishing"], mkt=c["spam"], normal=c["ham"],
                     todo=todo)
        print(f"{name:44s} {len(t):8d} {len(flagged):8d}  {c['smishing']:6d} {c['spam']:6d} {c['ham']:8d}  "
              f"{todo:8d} {missed if kept else '-':>7} {100 * c['ham'] / len(t):15.1f}")
    if total["received"]:
        print(f"{'all':44s} {total['received']:8d} {total['flagged']:8d}  {total['fraud']:6d} {total['mkt']:6d} "
              f"{total['normal']:8d}  {total['todo']:8d} {'':>7} {100 * total['normal'] / total['received']:15.1f}")
    print("Texts of SMS from phone numbers and of chats are kept only when flagged, so their missed scams\n"
          "cannot be counted ('-'), and the shares by label below count only their flagged ones.")


def measure_rows(rows):
    labelled = [r for r in rows if label_of(r) in LABELS]
    no_text = sum(1 for r in rows if not r.get("text"))
    not_study = sum(1 for r in rows if r.get("study") in (False, "False", "false"))
    print(f"{len(rows)} messages, {len(labelled)} labelled; {no_text} without text "
          "(safe messages from phone numbers and safe chats: the text is not kept"
          + (f"; {not_study} from phones not in the study" if not_study else "") + ")")
    print("Senders:", ", ".join(f"{k} {n}" for k, n in Counter(r['sender_kind'] for r in labelled).items()))
    phones = Counter((r.get("device") or "-") for r in labelled)
    if set(phones) != {"-"}:
        print("Labelled, by phone:", ", ".join(f"{k} {n}" for k, n in sorted(phones.items())))
        print("Received, by phone:", ", ".join(f"{k} {n}" for k, n in sorted(Counter(
            (r.get("device") or "-") for r in rows).items())))
    received_table(rows)
    table(labelled, "Labelled messages")
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
                  f"{(' '.join((r['text'] or '(text not stored)').split()))[:70]}")


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
    lb.add_argument("--device", help="only this phone's messages (the name typed in its app, e.g. C; - for none)")
    lb.add_argument("--again", action="store_true", help="also show messages labelled before")
    lb.add_argument("--flagged", action="store_true", help="only the messages the app flagged (to count false alarms)")
    m = sub.add_parser("measure")
    m.add_argument("sheet", nargs="?", help="a labelled CSV from 'export'; without it, the labels from 'label'")
    im = sub.add_parser("import")
    im.add_argument("sheet", help="a CSV from 'export' with the 'label' column filled")
    rv = sub.add_parser("review")
    for p in (e, lb, m, im, rv):
        p.add_argument("--log", default=DEFAULT_LOG)
        p.add_argument("--labels", default=DEFAULT_LABELS)
    a = ap.parse_args(argv)
    if a.cmd == "export":
        export(a.log, a.out, a.labels)
    elif a.cmd == "label":
        return label(a.log, a.labels, a.device, a.again, flagged=a.flagged)
    elif a.cmd == "import":
        return import_labels(a.sheet, a.labels)
    elif a.cmd == "review":
        return review(a.log, a.labels)
    elif a.sheet:
        measure(a.sheet)
    else:
        measure_log(a.log, a.labels)
    return 0


if __name__ == "__main__":
    sys.exit(main())

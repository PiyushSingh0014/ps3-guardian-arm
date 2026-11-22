"""Measure the sender rules (senders.SENDER_RULES) on real messages before they go live.

    python detectors/sms/eval_senders.py --india ~/india_sms_collection_v9.xlsx
    python detectors/sms/eval_senders.py --india ~/india_sms_collection_v9.xlsx --show    # which messages change
    python detectors/sms/eval_senders.py --india ~/india_sms_collection_v9.xlsx --apply   # switch on the rules that pass

The rules only ever take away some of the trust a registered sender ID (JD-HDFCBK-S) gives, so
they can catch more scams and can add false alarms, and only on messages from registered IDs.
Those are scored here as the app scores them (its own model, the links checked), once without
the new rules and once with each rule alone:
  - the India set's messages from registered IDs (labelled, never trained on);
  - the team's messages from registered IDs in the Pi's log (logs/sms_traffic.jsonl), labelled
    (data/sms/labels.json) or not. The log keeps every such text, so nothing is left out.
The rule, set before any measurement: a rule goes live only if, alone, it flags no more labelled
genuine messages (marketing or normal) than the app does without it. --apply writes the rules
that pass to data/sms/sender_rules.json, which the app reads at its next start.
Only counts are meant to leave the Pi; --show lists the messages that change, for you to read here.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, ROOT]
import train_baseline as tb  # noqa: E402
from detector import SmsDetector, decide, model_score  # noqa: E402
from senders import RULES_FILE, SENDER_RULES, active_rules, classify_sender  # noqa: E402
from train_v2 import LABELS, fill_digits, key, read_log  # noqa: E402

GENUINE = ("marketing", "normal")


def india_messages(path):
    from eval_india import read_test             # .xlsx needs openpyxl; a CSV needs nothing
    df, out, seen = read_test(path), [], set()
    for msg, lab, snd in zip(df.message, df.label, df.sender):
        k = key(msg)
        if classify_sender(snd).kind == "business" and k not in seen:
            seen.add(k)
            out.append({"text": msg, "sender": snd, "cls": LABELS[lab], "where": "india"})
    return out


def team_messages(log_path, labels_path):
    labels = {}
    if os.path.exists(labels_path):
        with open(labels_path, encoding="utf-8") as f:
            labels = json.load(f)
    out, seen = [], set()
    for e in read_log(log_path):
        if e.get("sender_kind") != "business" or not e.get("text"):
            continue
        k = (key(e["text"]), e.get("sender"))
        if k in seen:
            continue
        seen.add(k)
        out.append({"text": fill_digits(e["text"], e.get("id") or e["text"]), "sender": e.get("sender"),
                    "cls": LABELS.get(labels.get(e.get("id"), "")), "where": "team", "shown": e["text"]})
    return out


def score_all(detector, messages, variants):
    """Each message's verdict under each set of rules; the text is scored and its links checked once."""
    for m in messages:
        text = tb.clean_text(m["text"])
        links = detector.url.check_text(text) if detector.url else []
        base = model_score(*detector.text_probs(m["text"]), m["sender"])
        m["verdicts"] = {name: decide(base, text, m["sender"], links=links, rules=rules)[1]
                         for name, rules in variants.items()}


def counts(messages, variant):
    flagged = lambda ms: sum(1 for m in ms if m["verdicts"][variant] != "safe")  # noqa: E731
    india = [m for m in messages if m["where"] == "india" and m["cls"] in GENUINE]
    team = [m for m in messages if m["where"] == "team"]
    return {"india_genuine": flagged(india), "team_genuine": flagged([m for m in team if m["cls"] in GENUINE]),
            "team_fraud": flagged([m for m in team if m["cls"] == "fraud"]),
            "team_unlabelled": flagged([m for m in team if m["cls"] is None])}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--india", help="the India test set (.xlsx or .csv)")
    ap.add_argument("--log", default=os.path.join(ROOT, "logs", "sms_traffic.jsonl"))
    ap.add_argument("--labels", default=os.path.join(ROOT, "data", "sms", "labels.json"))
    ap.add_argument("--no-links", action="store_true", help="decide without checking the links")
    ap.add_argument("--show", action="store_true", help="list the messages whose verdict a rule changes")
    ap.add_argument("--apply", action="store_true", help="switch on the rules that pass (data/sms/sender_rules.json)")
    ap.add_argument("--rules-file", default=os.environ.get("GUARDIAN_SENDER_RULES", RULES_FILE))
    a = ap.parse_args(argv)

    detector = SmsDetector(url_detector=None if a.no_links else "auto")
    messages = (india_messages(os.path.expanduser(a.india)) if a.india else []) + team_messages(a.log, a.labels)
    variants = {"none (today)": frozenset()}
    variants.update({f"+ {r}": frozenset([r]) for r in SENDER_RULES})
    variants["all three"] = frozenset(SENDER_RULES)
    score_all(detector, messages, variants)

    india = [m for m in messages if m["where"] == "india"]
    team = [m for m in messages if m["where"] == "team"]
    tc = Counter(m["cls"] or "not labelled" for m in team)
    print(f"Messages from registered sender IDs: India set {len(india)} ({dict(Counter(m['cls'] for m in india))}); "
          f"team {len(team)} different ({dict(tc)})")
    print(f"Rules switched on now: {', '.join(sorted(active_rules(a.rules_file))) or 'none'}")
    n = {"india_genuine": sum(1 for m in india if m["cls"] in GENUINE),
         "team_genuine": sum(1 for m in team if m["cls"] in GENUINE),
         "team_fraud": tc.get("fraud", 0), "team_unlabelled": tc.get("not labelled", 0)}
    print("\nFlagged (suspicious or dangerous) as the app decides:")
    print(f"{'rules':14s} {'India genuine':>14s} {'team genuine':>13s} {'team scams':>11s} {'team not labelled':>18s}")
    print(f"{'':14s} {'of ' + str(n['india_genuine']):>14s} {'of ' + str(n['team_genuine']):>13s} "
          f"{'of ' + str(n['team_fraud']):>11s} {'of ' + str(n['team_unlabelled']):>18s}")
    table = {}
    for name in variants:
        c = table[name] = counts(messages, name)
        print(f"{name:14s} {c['india_genuine']:14d} {c['team_genuine']:13d} {c['team_fraud']:11d} "
              f"{c['team_unlabelled']:18d}")

    base = table["none (today)"]
    passing = []
    print("\nRule, set before measuring: a rule goes live only if, alone, it flags no more labelled genuine "
          "messages than today.")
    for r in SENDER_RULES:
        c = table[f"+ {r}"]
        extra = c["india_genuine"] + c["team_genuine"] - base["india_genuine"] - base["team_genuine"]
        caught = c["team_fraud"] - base["team_fraud"]
        ok = extra <= 0
        if ok:
            passing.append(r)
        print(f"  {r:7s} {'passes' if ok else 'does not pass'}: {extra:+d} genuine flagged, {caught:+d} scams caught, "
              f"{c['team_unlabelled'] - base['team_unlabelled']:+d} not-labelled messages flagged")

    if a.show:
        print("\nMessages whose verdict a rule changes (for reading here, not for sharing):")
        for r in SENDER_RULES:
            for m in messages:
                before, after = m["verdicts"]["none (today)"], m["verdicts"][f"+ {r}"]
                if before != after:
                    print(f"  {r:7s} {m['where']:5s} {m['cls'] or '?':10s} {before:>10s} -> {after:10s} "
                          f"{m['sender']:14s} {' '.join(m.get('shown', m['text']).split())[:80]}")

    if a.apply:
        os.makedirs(os.path.dirname(a.rules_file) or ".", exist_ok=True)
        with open(a.rules_file, "w", encoding="utf-8") as f:
            json.dump({"rules": passing, "date": time.strftime("%Y-%m-%d %H:%M"),
                       "measured_on": n, "flagged": table}, f, indent=1)
        print(f"\nWrote {a.rules_file}: {', '.join(passing) or 'no rule'} switched on. The app reads it at its next "
              "start: sudo systemctl restart ps3-guardian   (to switch them off: delete the file and restart)")
    elif passing:
        print("\nTo switch on the rules that pass, run this again with --apply, then: sudo systemctl restart ps3-guardian")
    return 0


if __name__ == "__main__":
    sys.exit(main())

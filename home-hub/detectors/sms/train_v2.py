"""SMS model v2: three classes (fraud, marketing, normal), learned from the public data and from
the team's own labelled messages. Run it on the Pi, where the messages are; nothing leaves it.

    python detectors/sms/train_v2.py --public ~/merged_sms.csv                     # measure only
    python detectors/sms/train_v2.py --public ~/merged_sms.csv --india ~/india_sms_collection_v9.xlsx
    python detectors/sms/train_v2.py --public ~/merged_sms.csv --india ... --save  # the app then uses v2

What changes from v1 (train_baseline.py):
  * Three classes instead of "threat or not", so genuine marketing need not count as fraud.
    In India only a registered sender ID may send marketing, so the app starts from the chance
    of fraud for a message from a registered ID (an offer is just an offer), and from the chance
    of fraud or marketing for any other sender, as v1 did (detector.model_score).
  * The team's labelled messages (logs/sms_traffic.jsonl with data/sms/labels.json, labelled with
    scripts/sms_traffic.py label) teach it Indian bank alerts, OTPs, deliveries and offers,
    which the public data hardly has.
  * The Pi's log writes '#' for every digit. For training, each '#' of a team message becomes
    a random digit, the same on every run (fill_digits): an OTP, an amount or an account number
    says nothing by its value, and the model sees digits where the real message had them, as
    it will in the app. (Reading every digit as 7 was tried first: OTPs then looked like the
    long premium-rate numbers of the public data's spam; see docs/sms-model-v2.md.)

Public labels: ham -> normal; Mishra & Soni's spam -> marketing and smishing -> fraud. UCI's spam
messages that Mishra & Soni also have take their label; the few that are only in UCI are left
out, because UCI does not say whether they are offers or scams.

How it is measured: copies are removed across all sources first (the team's label wins). A
message that is in the India test set, or a near-copy of one (the same template with other
names or amounts), never trains: the India set's genuine messages came from the team's phones
too. 30% of the public messages and 30% of the team's are held out (stratified, random_state
42). Three models learn from the rest:
  v1        two classes, public data only, digits as written (what the app used so far)
  3-class   three classes, public data only (shows what the classes alone change)
  v2        three classes, public and team data
Each is scored on the team's held-out messages, on the India test set and on the public
held-out messages, as the text alone and as the app decides (with the sender ID and the links).
With messages from two phones or more, each phone is also held out in turn: v2 then learns from
the other phones only, which shows how it does on a phone it has never seen.
The team's tables have two groups. The log always keeps the text of an SMS from a registered
sender ID (or another name), but from phone numbers and chats only when v1 flagged it: there v1
caught every scam by construction, and false alarms v2 would add are not seen. So the last lines
apply the rule of docs/sms-model-v2.md (step 5) to the India set and to the first group only.
With --save, v2 is trained again on everything and saved as detectors/sms/sms_v2.joblib, which
the app loads from its next start. That file is not in git: it learned from the team's messages.
"""
import argparse
import json
import os
import random
import re
import sys
import time
from collections import Counter

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, ROOT]
import train_baseline as tb  # noqa: E402

V2_MODEL = os.path.join(HERE, "sms_v2.joblib")
LABELS = {"smishing": "fraud", "spam": "marketing", "ham": "normal"}
CLASSES = ("fraud", "marketing", "normal")
COLUMNS = ["text", "cls", "origin", "sender", "key", "kept"]
NEAR_COPY = 0.7     # similarity of a template's variants ("OTP for Swiggy" / "OTP for Zomato": ~0.8)
MIN_PHONE = 10      # labelled messages a phone needs to be held out on its own


def key(text):
    """Copies: the same text once digits (or the log's '#'), spaces and capitals are set aside."""
    return " ".join(re.sub(r"[\d#]", "7", tb.clean_text(text)).lower().split())


def fill_digits(text, seed):
    """The log's '#' for each digit becomes a random digit, the same for the same seed."""
    rng = random.Random(str(seed))
    return re.sub("#", lambda _: str(rng.randrange(10)), text)


def near_copies(df, test, threshold=NEAR_COPY):
    """True for each row of df that is a near-copy of a message in test: the cosine similarity
    of their character n-grams is at least threshold."""
    if df.empty or test.empty:
        return pd.Series(False, index=df.index)
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit(list(df.key) + list(test.key))
    best = (vec.transform(df.key) @ vec.transform(test.key).T).max(axis=1).toarray().ravel()
    return pd.Series(best >= threshold, index=df.index)


def _dedupe(df):
    """One row per text; a text with two different labels is left out."""
    if df.empty:
        return df, 0
    conflict = df.groupby("key")["cls"].transform("nunique") > 1
    return df[~conflict].drop_duplicates("key").reset_index(drop=True), int(df.loc[conflict, "key"].nunique())


def load_public(path):
    df = tb.read_csv_any(path)
    if list(df.columns[:2]) == ["v1", "v2"]:
        df = df.rename(columns={"v1": "label", "v2": "message"})
    df = df.dropna(subset=["label", "message"]).copy()
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df["source"] = df["source"].astype(str) if "source" in df.columns else "public"
    df["key"] = df["message"].map(key)
    ms = df[df.source == "mishra_soni"]
    ms_label = dict(zip(ms.key, ms.label))
    rows, unsure = [], 0
    for msg, lab, src, k in zip(df.message, df.label, df.source, df.key):
        if src == "uci" and lab == "spam":
            lab = ms_label.get(k)                 # Mishra & Soni say offer or scam; UCI does not
            if lab is None:
                unsure += 1
                continue
        cls = LABELS.get(lab)
        if cls:
            rows.append({"text": msg, "cls": cls, "origin": f"public:{src}", "sender": "", "key": k, "kept": ""})
    out, conflicts = _dedupe(pd.DataFrame(rows, columns=COLUMNS))
    return out, unsure, conflicts


def read_log(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def sender_for(entry):
    """A sender the decision rules read as the app did: the log keeps a business's registered ID,
    but for a phone number only that it was one."""
    kind = entry.get("sender_kind")
    if kind == "business":
        return entry.get("sender") or ""
    return "9800000000" if kind == "mobile" else ""


def kept(entry):
    """Why the log has this message's text (app/sms_log.py): 'always' for an SMS from a registered
    sender ID or another name; 'flagged' for phone numbers and chats, kept only when v1 flagged
    them. On those, v1 caught every scam by construction, and v2's new false alarms are not seen."""
    always = entry.get("channel", "sms") == "sms" and entry.get("sender_kind") in ("business", "other")
    return "always" if always else "flagged"


def load_team(log_path, labels_path):
    labels = {}
    if os.path.exists(labels_path):
        with open(labels_path, encoding="utf-8") as f:
            labels = json.load(f)
    rows = []
    for e in read_log(log_path):
        cls = LABELS.get(labels.get(e.get("id"), ""))
        if cls and e.get("text"):
            rows.append({"text": fill_digits(e["text"], e.get("id") or e["text"]), "cls": cls,
                         "origin": f"team:{e.get('device') or '-'}", "sender": sender_for(e),
                         "key": key(e["text"]), "kept": kept(e)})
    return _dedupe(pd.DataFrame(rows, columns=COLUMNS))


def load_india(path):
    from eval_india import read_test             # .xlsx needs openpyxl; a CSV needs nothing
    df = read_test(path)
    out = pd.DataFrame({"text": df.message, "cls": df.label.map(LABELS), "origin": "india",
                        "sender": df.sender, "key": df.message.map(key), "kept": ""})
    return out.drop_duplicates("key").reset_index(drop=True)


def split(df):
    if len(df) < 10:
        return df, df.iloc[0:0]
    strat = df.cls if df.cls.value_counts().min() >= 2 else None
    return train_test_split(df, test_size=0.3, random_state=42, stratify=strat)


class Model:
    """One way of scoring: two classes (threat or normal, as v1) or three (fraud, marketing, normal)."""

    def __init__(self, name, frames, three):
        self.name, self.three = name, three
        df = pd.concat(frames, ignore_index=True)
        y = df.cls if three else (df.cls != "normal").astype(int)
        x, self.vec = tb.build_features(list(df.text), fit=True)          # cleans the text itself
        self.clf = LogisticRegression(max_iter=3000, class_weight="balanced").fit(x, y)
        self.col = list(self.clf.classes_).index("fraud" if three else 1)
        self.counts = dict(Counter(df.cls))

    def scores(self, texts, senders):
        """The score each message's decision starts from, as the app computes it (model_score)."""
        from detector import model_score
        x, _ = tb.build_features(list(texts), vec=self.vec)
        p = self.clf.predict_proba(x)
        normal = list(self.clf.classes_).index("normal" if self.three else 0)
        return [model_score(f, n, s or None) for f, n, s in zip(p[:, self.col], p[:, normal], senders)]


def verdicts(model, df, texts, links):
    """(text only, as the app decides) verdicts for each message of df."""
    from detector import decide
    alone, app = [], []
    for s, t in zip(model.scores(list(df.text), [None] * len(df)), texts):
        alone.append(decide(float(s), t, None, use_sender=False)[1])
    for s, t, snd, lk in zip(model.scores(list(df.text), list(df.sender)), texts, df.sender, links):
        app.append(decide(float(s), t, snd or None, use_sender=True, links=lk)[1])
    return alone, app


GROUPS = {"always": "SMS from sender IDs (every text is kept):",
          "flagged": "Phone numbers and chats (kept only when v1 flagged them):"}


def table(title, df, models, url):
    """Prints the share of each class flagged; the team's messages in the two groups of kept().
    Returns {model name: {(group, class): (messages, flagged as the app decides)}}."""
    counts = {m.name: {} for m in models}
    if df.empty:
        print(f"\n{title}: no messages")
        return counts
    print(f"\n{title}: {len(df)} messages. Share flagged (suspicious or dangerous):")
    names = [m.name for m in models]
    width = 8 * len(names) + 2 * (len(names) - 1)
    print(f"{'':12s} {'':>5s}   {'text only':^{width}s}   {'as the app (sender + links)':^{width}s}")
    print(f"{'label':12s} {'n':>5s}   " + "  ".join(f"{n:>8s}" for n in names) + "   "
          + "  ".join(f"{n:>8s}" for n in names))
    texts = [tb.clean_text(t) for t in df.text]                         # as the rules see them
    links = [url.check_text(t) if url else [] for t in texts]           # checked once for all models
    results = {m.name: verdicts(m, df, texts, links) for m in models}
    groups = [g for g in GROUPS if (df.kept == g).any()] or [""]
    for g in groups:
        if g:
            print(GROUPS[g])
        for cls in CLASSES:
            mask = ((df.cls == cls) & (df.kept == g)).tolist()
            n = sum(mask)
            if not n:
                continue
            cells = []
            for part in (0, 1):
                for m in models:
                    flagged = sum(1 for keep, x in zip(mask, results[m.name][part]) if keep and x != "safe")
                    cells.append(f"{flagged / n:8.0%}")
                    if part == 1:
                        counts[m.name][(g, cls)] = (n, flagged)
            print(f"{('  ' if g else '') + cls:12s} {n:5d}   " + "  ".join(cells[:len(models)]) + "   "
                  + "  ".join(cells[len(models):]))
    return counts


def rule(india, phones):
    """The rule for using v2 (docs/sms-model-v2.md, step 5), on the counts of table():
      1. India set: v2 catches as many of the scams as v1, give or take 2;
      2. each phone held out, SMS from sender IDs: v2 flags no more normal and marketing messages
         than v1 on any phone and fewer in all, and misses no more scams.
    Phone numbers and chats are left out of 2: the log has only the messages v1 flagged there."""
    print("\nRule (docs/sms-model-v2.md, step 5), as the app decides:")
    ok = bool(india)
    if india:
        n, v1 = india["v1"].get(("", "fraud"), (0, 0))
        v2 = india["v2"].get(("", "fraud"), (0, 0))[1]
        ok &= v2 >= v1 - 2
        print(f"  India set: scams caught v1 {v1}, v2 {v2} of {n}: {'ok' if v2 >= v1 - 2 else 'NOT ok'}")
    else:
        print("  India set: not given (--india): NOT ok")
    total1 = total2 = 0
    for phone, c in phones.items():
        def flagged(model, cls):
            return c[model].get(("always", cls), (0, 0))
        if not any(g == "always" for g, _ in c["v1"]):
            print(f"  Phone {phone}: no SMS from sender IDs, not checked")
            continue
        alarms1 = flagged("v1", "normal")[1] + flagged("v1", "marketing")[1]
        alarms2 = flagged("v2", "normal")[1] + flagged("v2", "marketing")[1]
        n, caught1 = flagged("v1", "fraud")
        caught2 = flagged("v2", "fraud")[1]
        good = alarms2 <= alarms1 and caught2 >= caught1
        ok &= good
        total1, total2 = total1 + alarms1, total2 + alarms2
        print(f"  Phone {phone}, SMS from sender IDs: normal and marketing flagged v1 {alarms1}, v2 {alarms2}; "
              f"scams caught v1 {caught1}, v2 {caught2} of {n}: {'ok' if good else 'NOT ok'}")
    fewer = total2 < total1
    ok &= fewer
    print(f"  All phones: normal and marketing flagged v1 {total1}, v2 {total2}: {'fewer, ok' if fewer else 'NOT fewer'}")
    print("  -> v2 passes: --save it, then restart" if ok else "  -> v2 does not pass: the app keeps v1")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--public", required=True, help="the public training CSV (merged_sms.csv)")
    ap.add_argument("--log", default=os.path.join(ROOT, "logs", "sms_traffic.jsonl"))
    ap.add_argument("--labels", default=os.path.join(ROOT, "data", "sms", "labels.json"))
    ap.add_argument("--india", help="the India test set (.xlsx or .csv): never trains, only tests")
    ap.add_argument("--no-links", action="store_true", help="decide without checking the links")
    ap.add_argument("--save", action="store_true", help="train v2 on everything and save it for the app")
    ap.add_argument("--out", default=V2_MODEL, help="where --save writes the model")
    a = ap.parse_args(argv)
    t0 = time.time()

    public, unsure, pub_conflicts = load_public(os.path.expanduser(a.public))
    team, team_conflicts = load_team(a.log, a.labels)
    india = load_india(os.path.expanduser(a.india)) if a.india else pd.DataFrame(columns=COLUMNS)
    public = public[~public.key.isin(set(team.key))]                 # the team's label wins
    n_pub, n_team = len(public), len(team)
    held = set(india.key)                                            # copies and near-copies never train
    public = public[~public.key.isin(held) & ~near_copies(public, india)]
    team = team[~team.key.isin(held) & ~near_copies(team, india)]
    print(f"Public: {len(public)} different messages {dict(Counter(public.cls))}; left out: {unsure} UCI-only "
          f"spam, {pub_conflicts} labelled two ways, {n_pub - len(public)} in the India set or near-copies")
    print(f"Team:   {len(team)} different labelled messages {dict(Counter(team.cls))}; "
          f"by phone {dict(Counter(team.origin))}; left out: {team_conflicts} labelled two ways, "
          f"{n_team - len(team)} in the India set or near-copies")
    if team.empty:
        print("No labelled team messages yet: label them first (python scripts/sms_traffic.py label).")

    pub_tr, pub_te = split(public)
    team_tr, team_te = split(team)
    models = [Model("v1", [pub_tr], three=False),
              Model("3-class", [pub_tr], three=True),
              Model("v2", [pub_tr, team_tr], three=True)]
    url = None
    if not a.no_links:
        from detectors.url.detector import UrlDetector
        url = UrlDetector()
    table("Team messages held out", team_te, models, url)
    india_counts = table("India test set", india, models, url) if not india.empty else None
    table("Public messages held out", pub_te, models, url)
    phones = sorted(p for p, n in Counter(team.origin).items() if n >= MIN_PHONE)
    phone_counts = {}
    if len(phones) >= 2:
        print("\nEach phone held out in turn: v2 learns from the public data and the other phones only.")
        for p in phones:
            unseen = Model("v2", [pub_tr, team[team.origin != p]], three=True)
            name = p.split(":", 1)[1]
            phone_counts[name] = table(f"Phone {name}", team[team.origin == p], [models[0], unseen], url)
    rule(india_counts, phone_counts)
    print(f"\n(trained on {len(pub_tr)} public and {len(team_tr)} team messages; {time.time() - t0:.0f} s)")

    if a.save:
        final = Model("v2", [public, team], three=True)
        joblib.dump({"clf": final.clf, "vec": final.vec, "version": 2, "classes": list(final.clf.classes_),
                     "trained_on": final.counts, "date": time.strftime("%Y-%m-%d %H:%M")}, a.out)
        print(f"\nSaved SMS model v2 ({sum(final.counts.values())} messages {final.counts}) -> {a.out}")
        print("The app uses it after: sudo systemctl restart ps3-guardian   (to go back: delete the file, restart)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Test the SMS detector on the India test set: real Indian messages never used for training.

    python detectors/sms/eval_india.py --train merged_sms.csv --test india_sms_collection_v9.xlsx
    python detectors/sms/eval_india.py --train merged_sms.csv --test india_test.csv --show 20

The model is trained exactly like train_baseline.py does it (same cleaning and
de-duplication, the same 70% split with random_state 42), so it is the model the app
uses. --all-data trains on 100% instead. Test messages that also appear in the training
data are dropped. Verdicts come from the app's own decision (detector.decide): score
>= 0.5 is suspicious, >= 0.8 dangerous, an .apk link is always dangerous, the sender
changes the odds (senders.py) and so do the links (detectors/url, unless --no-links).
Results are shown for the text alone, with the sender, and with the sender and links.

The test file is the collection workbook ('messages' sheet) or a CSV with the columns
label,message[,sender,category,language,origin]. Labels: smishing (fraud), spam
(genuine marketing), ham (normal).
"""
import argparse
import os
import sys

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(os.path.dirname(HERE))]
import train_baseline as tb  # noqa: E402
from detector import decide  # noqa: E402
from senders import classify_sender  # noqa: E402

LABELS = {"smishing": "fraud", "spam": "marketing", "ham": "normal"}


def read_test(path):
    if path.lower().endswith((".xlsx", ".xlsm")):
        from openpyxl import load_workbook
        ws = load_workbook(path, read_only=True, data_only=True)["messages"]
        rows = list(ws.iter_rows(values_only=True))
        head = [str(h or "").strip().lower() for h in rows[0]]
        df = pd.DataFrame([dict(zip(head, r)) for r in rows[1:]])
    else:
        df = pd.read_csv(path, keep_default_na=False)
    for col in ("label", "message", "sender", "category", "language", "origin"):
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str).str.strip()
    df["label"] = df["label"].str.lower()
    df = df[df.message != ""].reset_index(drop=True)
    bad = sorted(set(df.label) - set(LABELS))
    if bad:
        sys.exit(f"unknown labels {bad}: use smishing, spam or ham")
    return df


def train_model(train_path, all_data=False):
    full = tb.load(train_path)
    seen = set(full.message.map(tb.normalize))           # any overlap counts, not only the 70%
    df = full if all_data else train_test_split(full, test_size=0.3, random_state=42, stratify=full.y)[0]
    x, vec = tb.build_features(df.message.values, fit=True)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced").fit(x, df.y.values)
    return clf, vec, seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True, help="training CSV, e.g. merged_sms.csv")
    ap.add_argument("--test", required=True, help="collection workbook (.xlsx) or CSV")
    ap.add_argument("--all-data", action="store_true", help="train on 100%% instead of the app's 70%% split")
    ap.add_argument("--show", type=int, default=10, help="list this many misses and false alarms")
    ap.add_argument("--out", help="write every test message with its scores to this CSV")
    ap.add_argument("--no-links", action="store_true", help="do not check the links (detectors/url)")
    a = ap.parse_args()

    test = read_test(a.test)
    clf, vec, seen = train_model(a.train, a.all_data)
    test["norm"] = test.message.map(tb.normalize)
    overlap = test.norm.isin(seen)
    if overlap.any():
        print(f"Dropped {int(overlap.sum())} test messages that are also in the training data.")
    test = test[~overlap].drop_duplicates(subset="norm").reset_index(drop=True)

    x, _ = tb.build_features(test.message.tolist(), vec=vec)
    text_score = clf.predict_proba(x)[:, 1]
    texts = [tb.clean_text(m) for m in test.message]
    url = None
    if not a.no_links:
        from detectors.url.detector import UrlDetector
        url = UrlDetector()
        print("Links:", "model" if url.model else "rules only", "| lists:", url.blocklist.info().get("hosts", 0),
              "listed hosts,", len(url.top_sites), "top sites")
    checks = [url.check_text(t) if url else [] for t in texts]
    modes = [("text", False, False), ("sender", True, False)] + ([("links", True, True)] if url else [])
    for mode, use, with_links in modes:
        out = [decide(float(p), t, s or None, use_sender=use, links=c if with_links else None)
               for p, t, s, c in zip(text_score, texts, test.sender, checks)]
        test[f"score_{mode}"] = [round(o[0], 3) for o in out]
        test[f"verdict_{mode}"] = [o[1] for o in out]
    test["sender_kind"] = [classify_sender(s).kind for s in test.sender]
    test["links"] = ["; ".join(f"{v.host} {v.verdict}" for v in c) for c in checks]
    last = modes[-1][0]

    print(f"\nIndia test: {len(test)} messages "
          f"({'all-data' if a.all_data else 'app'} model, trained on {os.path.basename(a.train)})")
    print("Senders:", ", ".join(f"{k} {n}" for k, n in test.sender_kind.value_counts().items()))
    heads = {"text": "text only", "sender": "with sender", "links": "sender + links"}
    print(f"\n{'label':10s} {'messages':>8s}" + "".join(f" {'flagged, ' + heads[m]:>24s}" for m, _, _ in modes))
    for lab, name in LABELS.items():
        t = test[test.label == lab]
        if len(t):
            cells = []
            for m, _, _ in modes:
                f = int((t[f"verdict_{m}"] != "safe").sum())
                cells.append(f"{f:17d} ({f / len(t):4.0%})")
            print(f"{name:10s} {len(t):8d} " + " ".join(cells))
    print(f"\nFlagged {heads[last]}, by category (text only, with sender in brackets):")
    for (lab, cat), t in test.groupby(["label", "category"]):
        print(f"  {LABELS[lab]:9s} {cat or '-':24s} {int((t[f'verdict_{last}'] != 'safe').sum()):3d} of {len(t):3d}"
              f"  ({int((t.verdict_text != 'safe').sum())}, {int((t.verdict_sender != 'safe').sum())})")

    if a.show:
        miss = test[(test.label == "smishing") & (test[f"verdict_{last}"] == "safe")]
        print(f"\nMissed fraud, {heads[last]} (lowest score first):")
        for _, r in miss.sort_values(f"score_{last}").head(a.show).iterrows():
            print(f"  {r[f'score_{last}']:.2f}  [{r.sender_kind}] {tb.clean_text(r.message)[:110]}")
        fa = test[(test.label == "ham") & (test[f"verdict_{last}"] != "safe")]
        print(f"\nNormal messages flagged, {heads[last]} (highest score first):")
        for _, r in fa.sort_values(f"score_{last}", ascending=False).head(a.show).iterrows():
            print(f"  {r[f'score_{last}']:.2f}  [{r.category}, {r.sender_kind}] {tb.clean_text(r.message)[:100]}")
        if url:
            changed = test[test.verdict_sender != test.verdict_links]
            print(f"\nMessages whose verdict the links changed ({len(changed)}):")
            for _, r in changed.iterrows():
                print(f"  {LABELS[r.label]:9s} {r.verdict_sender:>10s} -> {r.verdict_links:10s} [{r.links[:60]}] "
                      f"{tb.clean_text(r.message)[:70]}")
    if a.out:
        test.drop(columns=["norm"]).to_csv(a.out, index=False, encoding="utf-8")
        print(f"\nWrote {a.out}")


if __name__ == "__main__":
    main()

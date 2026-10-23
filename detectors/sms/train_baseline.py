"""SMS scam / smishing baseline (v2.1).

v2 adds what merged public datasets need:
  * de-duplication BEFORE the train/test split. Public SMS datasets share many
    messages; without this, identical texts land in both train and test and the
    scores mostly measure memory, not detection;
  * removal of texts that different datasets label differently;
  * false-alarm rate, plus an error dump for error analysis;
  * an optional cross-source test: train on some datasets, test on another.
v2.1 cleans text the same way at training and prediction time: reads CSVs as
UTF-8 first (Hindi/Hinglish safe), repairs mojibake such as "IÂ’m" (with the
optional `ftfy` package), decodes HTML entities, and removes dataset artefacts
like UCI's "<#>" number placeholder, which are fingerprints of the dataset,
not of scams.

    python train_baseline.py --data merged_sms.csv
    python train_baseline.py --data merged_sms.csv --show-errors 15
    python train_baseline.py --data merged_sms.csv --no-dedupe          # old behaviour, to compare
    python train_baseline.py --data merged_sms.csv --holdout-source mishra_soni   # needs a 'source' column
    python train_baseline.py --predict "Your SBI KYC is pending, click short.example/x"

The saved model format is unchanged, so detector.py and the step-2 slice keep working.
"""
import argparse
import html
import os
import re
import sys

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

import joblib

from rules_india import extract_signals

try:                      # optional: `pip install ftfy` repairs mojibake like "IÂ’m"
    import ftfy
except ImportError:
    ftfy = None

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample_messages.csv")
MODEL = os.path.join(HERE, "sms_baseline.joblib")

_ARTEFACT_RE = re.compile(r"<#>|�")    # UCI number placeholder; lost characters


def clean_text(text):
    """Same cleaning for training and prediction (train-serve parity)."""
    t = html.unescape(str(text))
    if ftfy is not None:
        t = ftfy.fix_text(t)
    t = _ARTEFACT_RE.sub(" ", t)
    return " ".join(t.split())


def normalize(text):
    return clean_text(text).lower()


def read_csv_any(path):
    try:
        return pd.read_csv(path, encoding="utf-8")
    except UnicodeDecodeError:          # e.g. the original Kaggle UCI spam.csv
        return pd.read_csv(path, encoding="latin-1")


def load(path, dedupe=True):
    df = read_csv_any(path)
    # Accept the UCI format (columns v1,v2) as well as label,message[,source].
    if list(df.columns[:2]) == ["v1", "v2"]:
        df = df.rename(columns={"v1": "label", "v2": "message"})
    cols = ["label", "message"] + (["source"] if "source" in df.columns else [])
    df = df[cols].dropna(subset=["label", "message"]).copy()
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    # Anything that is not 'ham' is treated as a threat (spam / smishing -> 1).
    df["y"] = (df["label"] != "ham").astype(int)

    if dedupe:
        n0 = len(df)
        df["norm"] = df["message"].map(normalize)
        conflicted = df.groupby("norm")["y"].transform("nunique") > 1
        n_conflict = int(df.loc[conflicted, "norm"].nunique())
        df = df[~conflicted].drop_duplicates(subset="norm").drop(columns="norm")
        print(f"De-duplication: {n0} rows -> {len(df)} unique messages "
              f"({n0 - len(df)} removed, including {n_conflict} texts with conflicting labels)")
    return df.reset_index(drop=True)


def rule_matrix(messages):
    return np.array([extract_signals(m).vector() for m in messages], dtype=float)


def build_features(messages, vec=None, fit=False):
    messages = [clean_text(m) for m in messages]
    if fit:
        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                              min_df=1, max_features=20000)
        x_text = vec.fit_transform(messages)
    else:
        x_text = vec.transform(messages)
    x_rule = sparse.csr_matrix(rule_matrix(messages))
    return sparse.hstack([x_text, x_rule]).tocsr(), vec


def report(y_true, pred, proba, messages, show_errors=0):
    print(classification_report(y_true, pred, labels=[0, 1], target_names=["ham", "threat"],
                                digits=3, zero_division=0))
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    print("Confusion matrix [rows=true, cols=pred]:")
    print(cm)
    fpr = fp / max(tn + fp, 1)
    print(f"False alarms  : {fp} of {tn + fp} normal messages = {fpr:.2%} "
          f"(about {fpr * 1000:.1f} per 1,000 messages)")
    print(f"Missed threats: {fn} of {fn + tp} = {fn / max(fn + tp, 1):.1%}")

    if show_errors:
        order = np.argsort(-proba)                      # most confident first
        false_alarms = [i for i in order if y_true[i] == 0 and pred[i] == 1][:show_errors]
        missed = [i for i in order[::-1] if y_true[i] == 1 and pred[i] == 0][:show_errors]
        print("\n--- False alarms (normal messages the model flagged) ---")
        for i in false_alarms:
            print(f"  {proba[i]:.2f}  {clean_text(messages[i])[:150]}")
        print("\n--- Missed threats (threats the model let through) ---")
        for i in missed:
            print(f"  {proba[i]:.2f}  {clean_text(messages[i])[:150]}")


def train(data_path, dedupe=True, holdout_source=None, show_errors=0):
    df = load(data_path, dedupe=dedupe)
    print(f"Loaded {len(df)} messages  (threat={int(df.y.sum())}, "
          f"ham={int(len(df) - df.y.sum())})")

    if holdout_source:
        if "source" not in df.columns:
            sys.exit("--holdout-source needs a 'source' column in the CSV")
        is_test = df["source"].astype(str) == holdout_source
        if is_test.all() or not is_test.any():
            sys.exit(f"source '{holdout_source}' must be present but not be the only source")
        tr, te = df[~is_test], df[is_test]
        title = f"cross-source: trained without '{holdout_source}', tested on it"
    else:
        strat = df.y if df.y.sum() > 1 else None
        tr, te = train_test_split(df, test_size=0.3, random_state=42, stratify=strat)
        title = "held-out 30%"

    xtr, vec = build_features(tr.message.values, fit=True)
    xte, _ = build_features(te.message.values, vec=vec)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(xtr, tr.y.values)
    proba = clf.predict_proba(xte)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print(f"\n=== Evaluation ({title}) ===")
    report(te.y.values, pred, proba, te.message.values, show_errors)

    joblib.dump({"clf": clf, "vec": vec}, MODEL)
    print(f"\nSaved model -> {MODEL}")
    if holdout_source:
        print("Note: this model was trained without the held-out source; "
              "rerun without --holdout-source for your final model.")
    print("Try it:  python train_baseline.py --predict \"<a message>\"")


def predict(text):
    if not os.path.exists(MODEL):
        print("No model yet. Run `python train_baseline.py` first.")
        sys.exit(1)
    bundle = joblib.load(MODEL)
    x, _ = build_features([text], vec=bundle["vec"])
    p = float(bundle["clf"].predict_proba(x)[0, 1])
    sig = extract_signals(clean_text(text))
    verdict = "DANGEROUS" if p >= 0.8 else "SUSPICIOUS" if p >= 0.5 else "LIKELY SAFE"
    print(f"\nMessage : {text}")
    print(f"Score   : {p:.2f}  ->  {verdict}")
    if sig.reasons:
        print("Why     :")
        for r in sig.reasons:
            print(f"   - {r}")
    else:
        print("Why     : no India-specific red flags; verdict is from text patterns only")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=SAMPLE, help="CSV with columns label,message[,source]")
    ap.add_argument("--predict", help="classify a single message")
    ap.add_argument("--no-dedupe", action="store_true", help="skip de-duplication (old behaviour)")
    ap.add_argument("--holdout-source", help="test only on rows whose 'source' equals this")
    ap.add_argument("--show-errors", type=int, default=0, metavar="N",
                    help="print the N worst false alarms and missed threats")
    a = ap.parse_args()
    if a.predict:
        predict(a.predict)
    else:
        train(a.data, dedupe=not a.no_dedupe, holdout_source=a.holdout_source,
              show_errors=a.show_errors)

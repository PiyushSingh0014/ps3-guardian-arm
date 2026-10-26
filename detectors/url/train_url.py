"""Train the link model: how likely a website name belongs to a phishing site.

Data (scripts/get_url_data.py downloads it into data/url/):
  * PhiUSIIL Phishing URL Dataset (Prasad and Chandra, Computers & Security 2024; UCI
    dataset 967; CC BY 4.0): 134,850 legitimate and 100,945 phishing URLs.
  * Phishing.Database (Mitchell Krog, Nissar Chababy; MIT): phishing domains that were
    still online when last tested.
  * Chrome UX Report top 1 million websites (Google, CC BY 4.0; monthly copy at
    github.com/zakird/crux-top-lists): the websites Chrome users really visit, used as
    legitimate examples. PhiUSIIL alone has few Indian websites, and 45% of its .in
    domains are phishing, so a model trained on it alone flagged ordinary Indian sites.

Every legitimate URL in PhiUSIIL is a home page written as https://www.<domain>, while
its phishing URLs have paths, other schemes and subdomains. A model that sees whole URLs
learns that shortcut, and then every genuine link in an SMS (they all have paths) looks
like phishing. So:
  * the model sees only the registered domain, the part someone buys ("hdfcbank.com",
    "caringh-ochre.vercel.app"), each domain once;
  * the train/test split is by domain, so no domain is in both;
  * paths, short links, free hosting, brand names, IP addresses and the public lists of
    reported sites are handled by rules in detector.py, not learned.

    python detectors/url/train_url.py              # all three sources in data/url/
    python detectors/url/train_url.py --no-crux --no-phishing-db    # PhiUSIIL only

The model is saved as numbers only (model.py), so it loads with any scikit-learn version.
"""
import argparse
import gzip
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.url.features import HASHER, NUMERIC_NAMES, matrix, numeric   # noqa: E402
from detectors.url.links import parse_link                                   # noqa: E402
from detectors.url.model import LinkModel                                    # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "url_model.npz")
DATA = os.path.join(ROOT, "data", "url")
PHIUSIIL = os.path.join(DATA, "PhiUSIIL_Phishing_URL_Dataset.csv")
PHISHING_DB = os.path.join(DATA, "phishing-domains-ACTIVE.txt")
CRUX = os.path.join(DATA, "crux-top-1m.csv.gz")
TEST_DOMAINS = os.path.join(DATA, "url_test_domains.csv.gz")     # the held-out domains, for eval_url.py


def _rows(urls, phishing, source, rank=None):
    out = []
    ranks = rank if rank is not None else [0] * len(urls)
    for url, y, r in zip(urls, phishing, ranks):
        link = parse_link(url if "://" in url else "http://" + url)
        if link and not link.is_ip and link.registered:
            out.append((link.registered, link.domain, link.suffix, int(y), source, int(r)))
    return out


def load_phiusiil(path):
    df = pd.read_csv(path, usecols=["URL", "label"], encoding="utf-8-sig")
    return _rows(df["URL"].astype(str).tolist(), (1 - df["label"]).tolist(), "phiusiil")   # 1 = legitimate there


def load_host_list(path, phishing=1, source="phishing_db"):
    with open(path, encoding="utf-8", errors="replace") as f:
        hosts = [h.strip() for h in f if h.strip() and not h.startswith("#")]
    return _rows(hosts, [phishing] * len(hosts), source)


def load_crux(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        df = pd.read_csv(f)
    return _rows(df["origin"].astype(str).tolist(), [0] * len(df), "crux", df["rank"].tolist())


def domain_table(sources):
    """[(registered, domain, suffix, phishing, source, rank)] -> one row per registered domain.

    A domain with both labels (for example a popular site that a list reported) is dropped.
    """
    d = pd.DataFrame([r for rows in sources for r in rows],
                     columns=["registered", "domain", "suffix", "phishing", "source", "rank"])
    n_labels = d.groupby("registered")["phishing"].nunique()
    conflicts = set(n_labels[n_labels > 1].index)
    d = d[~d["registered"].isin(conflicts)]
    # Keep where each domain came from (the first source listed wins) and its best CrUX rank.
    crux_rank = d[d.source == "crux"].groupby("registered")["rank"].min()
    d = d.drop_duplicates("registered").copy()
    d["rank"] = d["registered"].map(crux_rank).fillna(0).astype(int)
    print(f"{len(d)} registered domains ({int(d.phishing.sum())} phishing, {int((1 - d.phishing).sum())} legitimate; "
          f"{len(conflicts)} with both labels dropped)")
    print("  by source:", ", ".join(f"{s} {n}" for s, n in d.source.value_counts().items()))
    return d.reset_index(drop=True)


def fit(train):
    pairs = list(zip(train["domain"], train["suffix"]))
    tfidf = TfidfTransformer(sublinear_tf=True).fit(HASHER.transform([f"{a}.{b}" for a, b in pairs]))
    scaler = StandardScaler().fit(np.array([numeric(a, b) for a, b in pairs], dtype=float))
    clf = LogisticRegression(C=2.0, max_iter=3000, class_weight="balanced", solver="liblinear")
    clf.fit(matrix(pairs, tfidf, scaler), train["phishing"].values)
    return LinkModel.from_sklearn(clf, tfidf, scaler), (clf, tfidf, scaler)


def rates(y, p, name, thresholds=(0.5, 0.8)):
    y, p = np.asarray(y), np.asarray(p)
    line = f"{name}: {len(y)} domains"
    if 0 < y.sum() < len(y):
        line += f", ROC AUC {roc_auc_score(y, p):.3f}"
    print(line)
    for t in thresholds:
        pred = p >= t
        if y.sum():
            print(f"  >= {t}: phishing caught {int((pred & (y == 1)).sum())}/{int(y.sum())} "
                  f"({(pred & (y == 1)).sum() / y.sum():.1%})", end="")
        if (y == 0).sum():
            print(f"{';' if y.sum() else ' '} legitimate flagged {int((pred & (y == 0)).sum())}/{int((y == 0).sum())} "
                  f"({(pred & (y == 0)).sum() / (y == 0).sum():.2%})", end="")
        print()


def report(test, p):
    rates(test.phishing.values, p, "Held-out domains, all sources (none seen in training)")
    for src in sorted(test.source.unique()):
        m = (test.source == src).values
        rates(test.phishing.values[m], p[m], f"  {src}")
    crux = test[(test.source == "crux")]
    if len(crux):
        print("  CrUX legitimate domains flagged at >= 0.5, by popularity:")
        for r in sorted(crux["rank"].unique()):
            m = ((test.source == "crux") & (test["rank"] == r)).values
            print(f"    top {r:>9,}: {(p[m] >= 0.5).mean():6.2%} of {m.sum()}")


def train(phiusiil=PHIUSIIL, phishing_db=PHISHING_DB, crux=CRUX, out=MODEL, test_size=0.2, seed=42,
          test_out=TEST_DOMAINS):
    t0 = time.time()
    sources = [load_phiusiil(phiusiil)]
    used = ["PhiUSIIL"]
    if crux and os.path.exists(crux):
        sources.append(load_crux(crux))
        used.append("CrUX top 1M")
    if phishing_db and os.path.exists(phishing_db):
        sources.append(load_host_list(phishing_db))
        used.append("Phishing.Database")
    d = domain_table(sources)
    tr, te = train_test_split(d, test_size=test_size, random_state=seed, stratify=d["phishing"])
    model, _ = fit(tr)
    p = model.scores(list(zip(te["domain"], te["suffix"])))
    print()
    report(te, p)
    model.meta = {"version": 2, "trained_on": used, "train_domains": int(len(tr)),
                  "test_domains": int(len(te)), "seed": seed, "date": time.strftime("%Y-%m-%d"),
                  "numeric": NUMERIC_NAMES}
    model.save(out)
    os.makedirs(os.path.dirname(test_out), exist_ok=True)
    te[["registered", "phishing", "source", "rank"]].to_csv(test_out, index=False, compression="gzip")
    print(f"\nSaved the link model -> {out} ({os.path.getsize(out) / 1e6:.1f} MB, {time.time() - t0:.0f} s)")
    print(f"Held-out domains for eval_url.py -> {test_out}")
    return model, tr, te


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--phiusiil", default=PHIUSIIL)
    ap.add_argument("--phishing-db", default=PHISHING_DB)
    ap.add_argument("--crux", default=CRUX)
    ap.add_argument("--no-phishing-db", action="store_true")
    ap.add_argument("--no-crux", action="store_true")
    ap.add_argument("--out", default=MODEL)
    a = ap.parse_args()
    if not os.path.exists(a.phiusiil):
        sys.exit(f"No {a.phiusiil}. Download the data first: python scripts/get_url_data.py --training")
    train(a.phiusiil, None if a.no_phishing_db else a.phishing_db, None if a.no_crux else a.crux, a.out)


if __name__ == "__main__":
    main()

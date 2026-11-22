"""Measure the link checker on links it has never seen.

    python detectors/url/eval_url.py --india india_sms_collection_v9.xlsx

Needs the files from scripts/get_url_data.py --training and from train_url.py (which saves
the held-out domains in data/url/url_test_domains.csv.gz). Every test link belongs to a
registered domain that the model did not see in training.

  A. The model alone, on the held-out registered domains.
  B. The whole checker (rules + model) on full held-out links, without the lists of known
     sites: that is what a brand-new phishing site meets.
  C. Indian phishing: held-out Phishing.Database hosts that use an Indian brand's name,
     against held-out popular websites under .in.
  D. The real links in the India SMS collection, link by link, without and with the lists.
"""
import argparse
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detectors.url.detector import MODEL, UrlDetector                            # noqa: E402
from detectors.url.links import find_links, parse_link                           # noqa: E402
from detectors.url.train_url import CRUX, PHIUSIIL, PHISHING_DB, TEST_DOMAINS    # noqa: E402

# Indian brand names as plain pieces of text, chosen independently of the checker's own
# patterns in lists.py, so set C does not just test those patterns against themselves.
INDIAN_WORDS = ("onlinesbi", "sbi-", "-sbi", "sbi.", "sbiyono", "yonosbi", "statebank", "hdfc", "icici", "axisbank",
                "kotak", "pnbindia", "bankofbaroda", "canarabank", "paytm", "phonepe", "npci", "bhim", "irctc",
                "indiapost", "india-post", "speedpost", "aadhaar", "uidai", "epfindia", "epfo-", "-epfo", "epfo.",
                "incometax", "income-tax", "licindia", "airtel", "myjio", "jio-", "-jio", "jio.", "jiomart",
                "jiofiber", "jiolottery", "jiorecharge", "bsnl", "bluedart", "delhivery", "dtdc")


def indian(host):
    return any(w in host for w in INDIAN_WORDS)


def pct(n, d):
    return f"{n}/{d} ({n / d:.1%})" if d else "-"


def line(name, verdicts, phishing):
    """Share flagged (suspicious or worse) and dangerous, for one test set."""
    v = np.array(verdicts)
    flagged, dangerous = int((v != "safe").sum()), int((v == "dangerous").sum())
    what = "caught" if phishing else "flagged"
    print(f"  {name:46s} {len(v):7d}   {what} {pct(flagged, len(v)):>20s}   dangerous {pct(dangerous, len(v)):>20s}")


def held_out_links(test):
    """One full link per held-out registered domain, from each source."""
    held = dict(zip(test.registered, test.phishing))
    sets = {}
    df = pd.read_csv(PHIUSIIL, usecols=["URL", "label"], encoding="utf-8-sig")
    for name, want in (("PhiUSIIL phishing URLs", 0), ("PhiUSIIL legitimate URLs", 1)):
        seen, out = set(), []
        for url in df.URL[df.label == want].astype(str):
            link = parse_link(url)
            if link and held.get(link.registered) == 1 - want and link.registered not in seen:
                seen.add(link.registered)
                out.append(link)
        sets[name] = out
    seen, out = set(), []
    with open(PHISHING_DB, encoding="utf-8", errors="replace") as f:
        for h in f:
            link = parse_link("http://" + h.strip()) if h.strip() and not h.startswith("#") else None
            if link and held.get(link.registered) == 1 and link.registered not in seen:
                seen.add(link.registered)
                out.append(link)
    sets["Phishing.Database hosts"] = out
    crux = pd.read_csv(CRUX)
    seen, out = set(), []
    for origin in crux.origin.astype(str):
        link = parse_link(origin)
        if link and held.get(link.registered) == 0 and link.registered not in seen:
            seen.add(link.registered)
            out.append(link)
    sets["CrUX popular websites"] = out
    return sets


def india_links(path):
    from detectors.sms.eval_india import read_test
    test = read_test(path)
    rows = []
    for label, msg in zip(test.label, test.message):
        for link in find_links(msg):
            rows.append((label, link))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--test-domains", default=TEST_DOMAINS)
    ap.add_argument("--india", help="the India SMS collection (.xlsx) or a CSV with label,message")
    a = ap.parse_args()

    bare = UrlDetector(model_path=a.model, intel_path=None, top_sites=None)      # rules + model only
    lists = UrlDetector(model_path=a.model)                                      # + blocklist and top sites
    print("Model:", bare.model.meta if bare.model else "none (rules only)")
    print("Lists:", lists.blocklist.info(), f"top sites {len(lists.top_sites)}")

    if os.path.exists(a.test_domains) and bare.model:
        test = pd.read_csv(a.test_domains)
        test = test.merge(pd.DataFrame([(r, d) for r in test.registered for d in [parse_link("http://" + r)]],
                                       columns=["registered", "link"]).drop_duplicates("registered"), on="registered")
        test = test[test.link.notna()]
        p = bare.model.scores([(k.domain, k.suffix) for k in test.link])
        print(f"\nA. The model alone, held-out registered domains ({len(test)})")
        from detectors.url.train_url import rates
        for src in sorted(test.source.unique()):
            m = (test.source == src).values
            rates(test.phishing.values[m], p[m], f"  {src}")

        print("\nB. The whole checker on held-out links, without the lists (suspicious or dangerous counts as caught)")
        sets = held_out_links(test)
        decided = Counter()
        for name, links in sets.items():
            vs = [bare.check_link(k) for k in links]
            line(name, [v.verdict for v in vs], phishing="phishing" in name.lower() or "Database" in name)
            decided.update(f"{name}: {v.kind}{' (decisive)' if v.decisive else ''}" for v in vs if v.verdict != "safe")
        print("  What flagged them (top reasons per set):")
        for name in sets:
            top = [(k.split(': ', 1)[1], n) for k, n in decided.most_common() if k.startswith(name + ":")][:5]
            print(f"    {name}: " + ", ".join(f"{k} {n}" for k, n in top))

        print("\nC. Indian phishing: held-out Phishing.Database hosts with an Indian brand's name, against held-out")
        print("   popular websites under .in (no lists)")
        ind = [k for k in sets["Phishing.Database hosts"] if indian(k.host)]
        line("Phishing.Database hosts, Indian brands", [bare.check_link(k).verdict for k in ind], True)
        legit_in = [k for k in sets["CrUX popular websites"] if k.suffix == "in" or k.suffix.endswith(".in")]
        line("CrUX popular websites under .in", [bare.check_link(k).verdict for k in legit_in], False)
        brand_legit = [k for k in sets["CrUX popular websites"] if indian(k.host)]
        line("CrUX popular websites with a brand's name", [bare.check_link(k).verdict for k in brand_legit], False)
    else:
        print(f"\n(no {a.test_domains} or no model: skipping A-C; run train_url.py first)")

    if a.india:
        rows = india_links(a.india)
        real = [(lab, k) for lab, k in rows]
        print(f"\nD. Links in the India SMS collection: {len(real)} links in {a.india}")
        print(f"   {'label':9s} {'link':30s} {'rules+model':>22s} {'with lists':>22s}  why")
        res = {"bare": Counter(), "lists": Counter()}
        for lab, k in sorted(real, key=lambda r: (r[0], r[1].registered)):
            vb, vl = bare.check_link(k), lists.check_link(k)
            res["bare"][(lab, vb.verdict)] += 1
            res["lists"][(lab, vl.verdict)] += 1
            print(f"   {lab:9s} {k.host[:30]:30s} {vb.verdict:>12s} {vb.score:5.2f}  {vl.verdict:>12s} {vl.score:5.2f}"
                  f"  {vl.kind}; {(vl.reasons or [''])[0][:60]}")
        for mode in ("bare", "lists"):
            for lab in ("ham", "spam", "smishing"):
                n = sum(c for (l2, _), c in res[mode].items() if l2 == lab)
                f = sum(c for (l2, v), c in res[mode].items() if l2 == lab and v != "safe")
                print(f"   {mode:5s} {lab:9s} flagged {pct(f, n)}")


if __name__ == "__main__":
    main()

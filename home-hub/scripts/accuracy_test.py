"""How accurate the app's message checks are, on labelled messages (update 49).

It runs the code the app runs on every message: the text model, the India rules, the sender
rules switched on in the app (cap and brand) and the link checker. The phone runs the same rules
(Phone Guard, compared on 16,272 messages), so these numbers are the phone's. Without --with-list
the Pi's phishing list is left out, as on the phone.

    python scripts/accuracy_test.py --india ~/india_sms_collection_v9.xlsx --public ~/merged_sms.csv \\
        --smishing ~/final_dataset_output.csv --out ../results/results_accuracy_run.md

Sets (any of them):
  --india SHEET     the India test set: 227 real messages (smishing, spam, ham) with typed sender IDs.
                    Used while building the rules, so it is not an untouched test.
  --public CSV      merged_sms.csv, only the 30% the SMS model never trained on (train_baseline's split).
  --smishing CSV    the IMC 2025 "Fishing for Smishing" reports (CC BY 4.0, github.com/reportsmishing/
                    Smishing-Dataset-IMC25), India rows only: one message per campaign (near-copies
                    merged), leaving out anything like the training data or the India set. Never used
                    to build anything. The reports hide links, numbers, dates and names behind
                    placeholders; they are put back as a link the checker cannot judge (*.example), a
                    test mobile number, a date and a name. Their senders are Indian mobile numbers.

A message counts as flagged when the app says suspicious or dangerous (it then shows an alert).
"""
import argparse
import csv
import math
import os
import re
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "detectors", "sms"), os.path.join(ROOT, "scripts")]

TEST_MOBILE = "9812345678"
PLACEHOLDERS = {"<URL>": "http://link.example/x", "<PHONE_NUMBER>": TEST_MOBILE, "<DATE_TIME>": "22/11/2026",
                "<NAMED_ENTITY>": "Rahul", "<EMAIL>": "help@mail.example"}
SAME_CAMPAIGN = 0.7          # cosine of character n-grams: near-copies (train_v2 uses the same)

# The India sheet's scam types and the alert titles (scam types) that name them. Types the app has
# no title of its own for are right when the alert is general.
EXPECTED = {
    "bank_kyc": {"bank_kyc_scam"}, "utility_disconnection": {"utility_disconnection_scam"},
    "lottery_reward": {"lottery_reward_scam"}, "job_task": {"job_task_scam"},
    "apk_link": {"apk_malware_link", "app_file"}, "delivery_fee": {"delivery_fee_scam"},
    "fake_offer": {"lottery_reward_scam"}, "loan_app": set(), "investment_trading": set(), "other_scam": set(),
}
GENERAL = {"generic_suspicious", "phishing_link", "promo_spam"}


def wilson(k, n, z=1.96):
    """95% interval of a share k/n (Wilson), in percent."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, mid - half), 100 * min(1.0, mid + half))


def share(k, n):
    if n == 0:
        return "–"
    lo, hi = wilson(k, n)
    return f"{k} of {n} ({100 * k / n:.1f}%, {lo:.0f}–{hi:.0f}%)"


def flagged(verdict):
    return verdict in ("suspicious", "dangerous")


class Run:
    """Checks messages and keeps (label, verdict, category, sender type, extra) per message."""

    def __init__(self, det):
        self.det = det
        self.ms = []

    def check(self, text, sender):
        t0 = time.perf_counter()
        f = self.det.check(text, sender=sender or None)
        self.ms.append(1000 * (time.perf_counter() - t0))
        return f


def table(rows, head):
    out = ["| " + " | ".join(head) + " |", "| " + " | ".join("---" for _ in head) + " |"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def confusion(results, labels):
    rows = []
    for lab in labels:
        got = Counter(r["verdict"] for r in results if r["label"] == lab)
        n = sum(got.values())
        if n:
            rows.append([lab, n, got["safe"], got["suspicious"], got["dangerous"]])
    return table(rows, ["Label", "Messages", "Safe", "Suspicious", "Dangerous"])


def summary_line(name, results, scam="scam", normal="normal", marketing="marketing"):
    s = [r for r in results if r["label"] == scam]
    n = [r for r in results if r["label"] == normal]
    m = [r for r in results if r["label"] == marketing]
    return [name, len(results), share(sum(flagged(r["verdict"]) for r in s), len(s)),
            share(sum(flagged(r["verdict"]) for r in n), len(n)),
            share(sum(flagged(r["verdict"]) for r in m), len(m))]


# ---------------------------------------------------------------- the sets

def india(run, path):
    from eval_india import read_test
    from detector import sender_type
    df = read_test(path)
    name = {"smishing": "scam", "spam": "marketing", "ham": "normal"}
    out = []
    for lab, msg, snd, cat in zip(df.label, df.message, df.sender, df.category):
        f = run.check(msg, snd)
        out.append({"label": name[lab], "verdict": f.verdict, "category": f.category, "type": cat,
                    "sender": sender_type(snd or None), "says": f.entities.get("says", [])})
    return out


def public(run, path):
    import train_baseline as tb
    from sklearn.model_selection import train_test_split
    df = tb.load(path)
    _, te = train_test_split(df, test_size=0.3, random_state=42, stratify=df.y)
    out = []
    for msg, y in zip(te.message, te.y):
        f = run.check(msg, None)
        out.append({"label": "scam or spam" if y else "normal", "verdict": f.verdict, "category": f.category})
    return out


def _vectors(texts, fit_on):
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True, sublinear_tf=True)
    vec.fit(fit_on)
    return vec


def smishing_messages(path, avoid):
    """India reports, placeholders put back, exact copies merged, one per campaign, none like `avoid`."""
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("original_network_country") == "IND"]
    counts, kind = Counter(), {}
    for r in rows:
        t = (r.get("text") or "").strip()
        if not t:
            continue
        counts[t] += 1
        kind.setdefault(t, r.get("scam_type") or "others")
    texts = [t for t, _ in counts.most_common()]          # the most reported first: they lead a campaign
    vec = _vectors(texts, texts + list(avoid))
    x = vec.transform(texts)
    near_known = set()
    if avoid:
        a = vec.transform(list(avoid))
        sims = (x @ a.T).max(axis=1).toarray().ravel()
        near_known = {i for i, s in enumerate(sims) if s >= SAME_CAMPAIGN}
    leads, members = [], defaultdict(int)
    for i in range(len(texts)):
        if i in near_known:
            continue
        if leads:
            s = (x[i] @ x[leads].T).toarray().ravel()
            j = int(s.argmax())
            if s[j] >= SAME_CAMPAIGN:
                members[leads[j]] += counts[texts[i]]
                continue
        leads.append(i)
        members[i] += counts[texts[i]]
    picked = []
    for i in leads:
        t = texts[i]
        for ph, value in PLACEHOLDERS.items():
            t = t.replace(ph, value)
        t = re.sub(r"<[A-Z_]+>", "", t)
        picked.append({"text": t, "raw": texts[i], "type": kind[texts[i]], "reports": members[i]})
    info = {"reports": len(rows), "different": len(texts), "like_known": len(near_known), "campaigns": len(leads)}
    return picked, info


def smishing(run, path, avoid):
    picked, info = smishing_messages(path, avoid)
    out, nolink = [], []
    for p in picked:
        label = "spam" if p["type"] == "spam" else "scam"
        f = run.check(p["text"], TEST_MOBILE)
        out.append({"label": label, "verdict": f.verdict, "category": f.category, "type": p["type"],
                    "says": f.entities.get("says", [])})
        bare = re.sub(r"\s+", " ", re.sub(r"<URL>", "", p["raw"]))
        for ph, value in PLACEHOLDERS.items():
            if ph != "<URL>":
                bare = bare.replace(ph, value)
        g = run.check(re.sub(r"<[A-Z_]+>", "", bare), TEST_MOBILE)
        nolink.append({"label": label, "verdict": g.verdict})
    return out, nolink, info


# ---------------------------------------------------------------- the report

def by_group(results, key, label="scam"):
    rows = []
    groups = Counter(r[key] for r in results if r["label"] == label)
    for g, n in groups.most_common():
        k = sum(flagged(r["verdict"]) for r in results if r["label"] == label and r[key] == g)
        rows.append([g or "(none)", share(k, n)])
    return rows


def titles(results):
    """For caught scams with a known type: is the alert's title the right kind of scam?"""
    right = general = wrong = 0
    wrong_pairs = Counter()
    for r in results:
        if r["label"] != "scam" or not flagged(r["verdict"]) or r["type"] not in EXPECTED:
            continue
        want = EXPECTED[r["type"]]
        if r["category"] in want or (not want and r["category"] in GENERAL):
            right += 1
        elif r["category"] in GENERAL:
            general += 1
        else:
            wrong += 1
            wrong_pairs[(r["type"], r["category"])] += 1
    return right, general, wrong, wrong_pairs


def report(sets, ms, args, det_name, links):
    lines = ["# Accuracy of the message checks", "",
             f"Run {time.strftime('%Y-%m-%d %H:%M')} on {os.uname().machine}, Python {sys.version.split()[0]}. "
             f"SMS model {det_name}; sender rules {', '.join(args.rules) or 'none'}; link checker {links}.", "",
             "Flagged = the app says suspicious or dangerous and shows an alert. In brackets: the share and its "
             "95% interval.", ""]
    rows = []
    if "india" in sets:
        rows.append(summary_line("India test set (typed sender IDs)", sets["india"]))
    if "public" in sets:
        r = summary_line("Public, held out (no sender)", sets["public"], scam="scam or spam")
        r[4] = "–"
        rows.append(r)
    if "smishing" in sets:
        r = summary_line("Fishing for Smishing, India (one per campaign)", sets["smishing"][0])
        r[3] = "–"
        r[4] = share(sum(flagged(x["verdict"]) for x in sets["smishing"][0] if x["label"] == "spam"),
                     sum(1 for x in sets["smishing"][0] if x["label"] == "spam")) + " (spam)"
        rows.append(r)
    lines += [table(rows, ["Set", "Messages", "Scams flagged", "Normal flagged (false alarms)", "Marketing flagged"]), ""]
    if ms:
        lines += [f"Time per message on this machine: median {statistics.median(ms):.1f} ms, "
                  f"95th percentile {sorted(ms)[int(0.95 * (len(ms) - 1))]:.1f} ms ({len(ms):,} checks).", ""]

    if "india" in sets:
        res = sets["india"]
        lines += ["## India test set", "", confusion(res, ["scam", "marketing", "normal"]), "",
                  "Scams by type:", "", table(by_group(res, "type"), ["Type", "Flagged"]), "",
                  "Normal messages flagged, by type:", "", table(by_group(res, "type", "normal"), ["Type", "Flagged"]), "",
                  "By sender (typed in the sheet):", "",
                  table(sender_rows(res), ["Sender", "Scams flagged", "Normal flagged", "Marketing flagged"]), ""]
        right, general, wrong, pairs = titles(res)
        n = right + general + wrong
        lines += ["Does the alert name the right kind of scam? (caught scams with a known type)", "",
                  table([["Right", share(right, n)], ["General (\"Suspicious message\", \"Phishing link\")", share(general, n)],
                         ["Wrong kind", share(wrong, n)]], ["Title", "Alerts"]), ""]
        if pairs:
            lines += ["Wrong kinds: " + "; ".join(f"{t} named {c} ({k})" for (t, c), k in pairs.most_common()) + ".", ""]
        said = [r for r in res if r["label"] == "scam" and flagged(r["verdict"])]
        lines += [f"Caught scams with at least one phrase of what the message says (prompt v5): "
                  f"{share(sum(bool(r['says']) for r in said), len(said))}.", ""]

    if "public" in sets:
        res = sets["public"]
        lines += ["## Public messages, held out", "", "The 30% of merged_sms.csv (UCI SMS Spam Collection and "
                  "Mishra & Soni) the SMS model never trained on; no sender, so text and links only.", "",
                  confusion(res, ["scam or spam", "normal"]), ""]

    if "smishing" in sets:
        res, nolink, info = sets["smishing"]
        lines += ["## Fishing for Smishing: Indian scam reports", "",
                  f"{info['reports']:,} reports from Indian mobile numbers, {info['different']:,} different texts; "
                  f"{info['like_known']:,} left out as like the training data or the India set; "
                  f"{info['campaigns']:,} campaigns (one message each).", "",
                  confusion(res, ["scam", "spam"]), "", "Scams by the reporters' type:", "",
                  table(by_group(res, "type"), ["Type", "Flagged"]), "",
                  f"With the link left out (the reports hide it): scams flagged "
                  f"{share(sum(flagged(r['verdict']) for r in nolink if r['label'] == 'scam'), sum(1 for r in nolink if r['label'] == 'scam'))}.", ""]
        said = [r for r in res if r["label"] == "scam" and flagged(r["verdict"])]
        lines += [f"Caught scams with at least one phrase of what the message says: "
                  f"{share(sum(bool(r['says']) for r in said), len(said))}.", ""]
    return "\n".join(lines)


def sender_rows(res):
    rows = []
    for g, _ in Counter(r["sender"] for r in res).most_common():
        cells = [g]
        for lab in ("scam", "normal", "marketing"):
            sel = [r for r in res if r["sender"] == g and r["label"] == lab]
            cells.append(share(sum(flagged(r["verdict"]) for r in sel), len(sel)))
        rows.append(cells)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--india")
    ap.add_argument("--public")
    ap.add_argument("--smishing")
    ap.add_argument("--model", help="the SMS model (default: the app's, detectors/sms/sms_baseline.joblib)")
    ap.add_argument("--rules", default=None, help="sender rules, comma-separated (default: the app's, cap,brand)")
    ap.add_argument("--with-list", action="store_true", help="also the Pi's phishing list (the phone has none)")
    ap.add_argument("--out", help="also write the report here (Markdown)")
    a = ap.parse_args(argv)
    if not (a.india or a.public or a.smishing):
        ap.error("give at least one of --india, --public, --smishing")

    import export_phone_guard
    a.rules = export_phone_guard.SENDER_RULES_ON if a.rules is None else [r for r in a.rules.split(",") if r]
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    tmp.write('{"rules": [%s]}' % ", ".join(f'"{r}"' for r in a.rules))
    tmp.close()
    os.environ["GUARDIAN_SENDER_RULES"] = tmp.name

    from detector import SmsDetector
    from detectors.url.detector import UrlDetector
    url = UrlDetector() if a.with_list else UrlDetector(intel_path=None)
    det = SmsDetector(model_path=a.model, url_detector=url)
    run = Run(det)
    sets = {}
    if a.india:
        sets["india"] = india(run, os.path.expanduser(a.india))
    if a.public:
        sets["public"] = public(run, os.path.expanduser(a.public))
    if a.smishing:
        avoid = []
        if a.public:
            import train_baseline as tb
            avoid += list(tb.load(os.path.expanduser(a.public)).message)
        if a.india:
            from eval_india import read_test
            avoid += list(read_test(os.path.expanduser(a.india)).message)
        sets["smishing"] = smishing(run, os.path.expanduser(a.smishing), avoid)
    os.unlink(tmp.name)
    text = report(sets, run.ms, a, det.model_name, "with the Pi's phishing list" if a.with_list else
                  "without a phishing list, as on the phone")
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

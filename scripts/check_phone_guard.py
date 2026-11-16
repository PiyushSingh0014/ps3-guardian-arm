"""Does the phone decide as the Pi does? (update 43)

The phone's checks (android/.../guard/) are a Kotlin copy of the Pi's Python checks. This script
makes a set of test messages, has the Pi's code judge them, and compares the answers with what the
phone's code wrote for the same messages (android/guard-check/ runs it on a computer):

    python scripts/check_phone_guard.py inputs  --india ~/india_sms_collection_v9.xlsx --public ~/merged_sms.csv --out /tmp/in.jsonl
    java -jar guard-check.jar android/app/src/main/assets/guard /tmp/in.jsonl /tmp/phone.jsonl
    python scripts/check_phone_guard.py compare --sms-model MODEL --inputs /tmp/in.jsonl --phone /tmp/phone.jsonl

The Pi's side runs without the public phishing list, as the phone does, and with the sender rules
switched on on the Pi (cap and brand).
"""
import argparse
import gzip
import json
import os
import random
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "detectors", "sms"))

SENDERS = ["", "JD-HDFCBK-S", "VM-AIRTEL-P", "AX-SBIBNK-T", "9812345678", "+91 98123 45678", "HDFCBK", "Mom"]
EDGE = [
    "Your SBI a/c is blocked. Update KYC at hxxps://sbi-kyc-update.xyz/verify now",
    "Download the app: http://bit.ly/3xYz and install Bank_Update.apk",
    "Pay at https://www.sbi.co.in@evil-pay.top/login",
    "See https://www-sbi-co-in.translate.goog/kyc?x=1",
    "https://cdn.ampproject.org/c/s/sbi-kyc-help.online/verify",
    "Go to https://www.google.com/url?q=https://paytm-kyc-update.click/verify&sa=D",
    "Login http://192.168.1.20/admin and http://45.33.12.9/kyc",
    "Visit xn--sbi-qpa.com/login for your refund",
    "आपका खाता बंद हो जाएगा। KYC अपडेट करें: https://sbi-kyc.top/a",
    "Win ₹5000!! 🎉 Claim at www.lucky-draw.club/claim 😀",
    "Itâ€™s your “last chance” — click&nbsp;here &amp; win &#8377;500",
    "Hi\x92s it ok? \x93yes\x94 – fine",
    "Wedding_Invitation.apk",
    "Dear customer, your electricity will be disconnected tonight. Call 9876543210",
    "Your OTP is 482913. Do not share it with anyone. - HDFC Bank",
    "Share the OTP sent to your phone to receive the cashback of Rs 500",
    "Parcel held at customs, pay fee at indiapost-redeliver.com/pay",
    "Work from home, earn Rs 3000 daily: https://t.me/jobs_daily",
    "Your Aadhaar is blocked, update at https://uidai.gov.in/update",
    "Check sites.google.com/view/sbi-kyc-login and forms.gle/abc",
    "Hello B.Tech students, Ref.ID 22, meet Mr.Sharma at placement.To office",
    "Your HDFC credit card bill of Rs 4,500 is due. Pay at https://hdfcbank.bank.in/pay",
]


def make_inputs(a):
    rows = []
    if a.india:
        from eval_india import read_test
        df = read_test(a.india)
        for msg, snd in zip(df["message"], df["sender"]):
            for s in [snd] + SENDERS:
                rows.append({"text": msg, "sender": s, "set": "india"})
    if a.public:
        import train_baseline as tb
        df = tb.load(a.public)
        for msg in df["message"]:
            rows.append({"text": msg, "sender": "", "set": "public"})
    for e in EDGE:
        for s in SENDERS:
            rows.append({"text": e, "sender": s, "set": "edge"})
    rng = random.Random(43)
    domains = []
    data = os.path.join(ROOT, "data", "url")
    for name, n in (("phishing-domains-ACTIVE.txt", 3000), ("top_sites.txt", 2000)):
        path = os.path.join(data, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = [x.strip() for x in f if x.strip() and not x.startswith("#")]
            domains += rng.sample(lines, min(n, len(lines)))
    test = os.path.join(data, "url_test_domains.csv.gz")
    if os.path.exists(test):
        with gzip.open(test, "rt", encoding="utf-8", errors="replace") as f:
            lines = [x.split(",")[0].strip() for x in f][1:]
        domains += rng.sample(lines, min(3000, len(lines)))
    shapes = ["Open https://{}/login?id=7", "visit www.{} today", "{}/kyc", "{}", "http://secure.{}/account"]
    for i, d in enumerate(domains):
        rows.append({"text": shapes[i % len(shapes)].format(d), "sender": "", "set": "links"})
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{len(rows):,} test messages -> {a.out}")


def compare(a):
    rules = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"rules": ["cap", "brand"]}, rules)
    rules.close()
    os.environ["GUARDIAN_SENDER_RULES"] = rules.name
    import train_baseline as tb
    from detectors.sms.detector import SmsDetector
    from detectors.url.detector import UrlDetector
    det = SmsDetector(model_path=a.sms_model, url_detector=UrlDetector(intel_path=None))
    with open(a.inputs, encoding="utf-8") as f:
        inputs = [json.loads(x) for x in f]
    with open(a.phone, encoding="utf-8") as f:
        phone = [json.loads(x) for x in f]
    if len(inputs) != len(phone):
        sys.exit(f"{len(inputs)} inputs but {len(phone)} answers from the phone")
    by_set, problems = {}, []
    for inp, ph in zip(inputs, phone):
        f_ = det.check(inp["text"], inp["sender"] or None)
        links = det.url.check_text(tb.clean_text(inp["text"]))
        diffs = []
        if tb.clean_text(inp["text"]) != ph["clean"]:
            diffs.append("clean")
        if f_.verdict != ph["verdict"]:
            diffs.append(f"verdict {f_.verdict} / {ph['verdict']}")
        if abs(f_.score - ph["score"]) > 0.0011:
            diffs.append(f"score {f_.score} / {ph['score']}")
        if f_.category != ph["category"]:
            diffs.append(f"category {f_.category} / {ph['category']}")
        if list(f_.reasons) != ph["reasons"]:
            diffs.append("reasons")
        py_links = [(v.host, v.verdict, v.kind, v.decisive, list(v.reasons)) for v in links]
        ph_links = [(v["host"], v["verdict"], v["kind"], v["decisive"], v["reasons"]) for v in ph["links"]]
        if py_links != ph_links:
            diffs.append("links")
        elif any(abs(v.score - w["score"]) > 0.00011 for v, w in zip(links, ph["links"])):
            diffs.append("link scores")
        s = by_set.setdefault(inp["set"], {"n": 0, "same": 0, "verdict": 0, "flagged_py": 0, "flagged_phone": 0})
        s["n"] += 1
        s["same"] += not diffs
        s["verdict"] += f_.verdict == ph["verdict"]
        s["flagged_py"] += f_.verdict != "safe"
        s["flagged_phone"] += ph["verdict"] != "safe"
        if diffs:
            problems.append((inp, diffs, f_, ph))
    print(f"{'set':8s} {'messages':>9s} {'all the same':>13s} {'same verdict':>13s} {'flagged: Pi / phone':>20s}")
    for k, s in by_set.items():
        print(f"{k:8s} {s['n']:9,} {s['same']:13,} {s['verdict']:13,} {s['flagged_py']:>9,} / {s['flagged_phone']:,}")
    for inp, diffs, f_, ph in problems[:a.show]:
        print("\n" + "; ".join(diffs) + f"  [{inp['set']}] sender={inp['sender']!r}")
        print("  text :", inp["text"][:150])
        if "reasons" in diffs or "links" in diffs:
            print("  Pi   :", f_.reasons)
            print("  phone:", ph["reasons"])
    os.unlink(rules.name)
    return 0 if not problems else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("inputs")
    m.add_argument("--india")
    m.add_argument("--public")
    m.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--sms-model", required=True)
    c.add_argument("--inputs", required=True)
    c.add_argument("--phone", required=True)
    c.add_argument("--show", type=int, default=15)
    a = ap.parse_args(argv)
    if a.cmd == "inputs":
        make_inputs(a)
        return 0
    return compare(a)


if __name__ == "__main__":
    sys.exit(main())

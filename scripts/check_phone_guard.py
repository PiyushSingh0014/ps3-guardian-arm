"""Does the phone decide as the Pi does? (update 43; Llama's prompt and answer checks: update 44)

The phone's checks (android/.../guard/) are a Kotlin copy of the Pi's Python checks. This script
makes a set of test messages, has the Pi's code judge them, and compares the answers with what the
phone's code wrote for the same messages (android/guard-check/ runs it on a computer):

    python scripts/check_phone_guard.py inputs  --india ~/india_sms_collection_v9.xlsx --public ~/merged_sms.csv --out /tmp/in.jsonl
    java -jar guard-check.jar android/app/src/main/assets/guard /tmp/in.jsonl /tmp/phone.jsonl
    python scripts/check_phone_guard.py compare --sms-model MODEL --inputs /tmp/in.jsonl --phone /tmp/phone.jsonl

The Pi's side runs without the public phishing list, as the phone does, and with the sender rules
switched on on the Pi (cap and brand). For each message that Llama would explain, the comparison
also covers who the message claims to be, the case Llama is shown and the whole prompt in English
and Hindi (as SHA-256: identical text).

The answer checker (advisor/validator.py, which holds Llama's text to the case before a user sees
it) is compared on Llama answers: the worked examples, Llama's graded answers from the Pi if given
(--graded, the JSONL of eval answers with "case" and "answer"), and variants that add sentences
with numbers, links, organisations, rules, hedges, contradictions and cut-off ends:

    python scripts/check_phone_guard.py answers --graded answers.jsonl --out /tmp/ans.jsonl
    java -jar guard-check.jar --answers android/app/src/main/assets/guard /tmp/ans.jsonl /tmp/ans_phone.jsonl
    python scripts/check_phone_guard.py compare-answers --answers /tmp/ans.jsonl --phone /tmp/ans_phone.jsonl
"""
import argparse
import dataclasses
import gzip
import hashlib
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
    from advisor.advise import SKIP_LLM_SEVERITIES
    from advisor.playbooks import get_playbook, load_playbooks
    from advisor.prompt import build_prompt, case_text, max_new_tokens
    books = load_playbooks()
    det = SmsDetector(model_path=a.sms_model, url_detector=UrlDetector(intel_path=None))

    def sha(text):
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def llama(f_):
        """What the phone's LlamaText.prompt should give for this finding: None, or the case and prompts."""
        book = get_playbook(books, f_.category)
        if f_.verdict == "safe" or book.severity in SKIP_LLM_SEVERITIES:
            return None
        en, hi = dataclasses.replace(f_, language="en"), dataclasses.replace(f_, language="hi")
        return {"case": case_text(en, book), "prompt_en": sha(build_prompt(en, book)),
                "prompt_hi": sha(build_prompt(hi, book)), "max_new_en": max_new_tokens("en"),
                "max_new_hi": max_new_tokens("hi")}
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
        claims = (f_.entities.get("claims_to_be"), f_.entities.get("claims_kind"))
        if claims != (ph.get("claims_to_be"), ph.get("claims_kind")):
            diffs.append(f"claims {claims} / {(ph.get('claims_to_be'), ph.get('claims_kind'))}")
        want = llama(f_)
        if want != ph.get("llama", "missing"):
            diffs.append("llama prompt")
        s = by_set.setdefault(inp["set"], {"n": 0, "same": 0, "verdict": 0, "flagged_py": 0, "flagged_phone": 0,
                                           "prompts": 0, "prompts_same": 0})
        s["n"] += 1
        s["same"] += not diffs
        s["verdict"] += f_.verdict == ph["verdict"]
        s["flagged_py"] += f_.verdict != "safe"
        s["flagged_phone"] += ph["verdict"] != "safe"
        s["prompts"] += want is not None
        s["prompts_same"] += want is not None and want == ph.get("llama")
        if diffs:
            problems.append((inp, diffs, f_, ph, want))
    print(f"{'set':8s} {'messages':>9s} {'all the same':>13s} {'same verdict':>13s} {'flagged: Pi / phone':>20s}"
          f" {'Llama prompts: same':>20s}")
    for k, s in by_set.items():
        print(f"{k:8s} {s['n']:9,} {s['same']:13,} {s['verdict']:13,} {s['flagged_py']:>9,} / {s['flagged_phone']:<8,}"
              f" {s['prompts']:>9,}: {s['prompts_same']:,}")
    for inp, diffs, f_, ph, want in problems[:a.show]:
        print("\n" + "; ".join(diffs) + f"  [{inp['set']}] sender={inp['sender']!r}")
        print("  text :", inp["text"][:150])
        if "reasons" in diffs or "links" in diffs:
            print("  Pi   :", f_.reasons)
            print("  phone:", ph["reasons"])
        if "llama prompt" in diffs and want and ph.get("llama"):
            print("  Pi case   :", want["case"].replace("\n", " | ")[:300])
            print("  phone case:", ph["llama"]["case"].replace("\n", " | ")[:300])
    os.unlink(rules.name)
    return 0 if not problems else 1


# Sentences that each test one of the answer checker's rules (advisor/validator.py).
EXTRA_EN = [
    "Call 9876543210 now to keep your account open.", "Visit https://sbi-kyc-help.xyz/verify to check it.",
    "Report it at cybercrime.gov.in or call 1930.", "Real banks never ask for your PIN in a message.",
    "This message is likely a scam that wants your OTP.", "It is probably a scam.",
    "Update your Know Your Credentials only in the official app.", "This message is safe and you can trust it.",
    "It is not a scam, so there is no need to worry.", "The link ends in .bank.in, so it looks official.",
    "Links ending in .gov.in are not real government websites.", "Rs. 500 was promised as cashback.",
    "SBI always sends messages like this.", "No bank will ever ask for your OTP.",
    "The scammer wants 2 lakh rupees within 24 hours.", "Paytm and PhonePe are being copied here.",
    "WhatsApp and Telegram chats like this are common.", "Genuine companies do not send such links, e.g. this one.",
    "Mr. Sharma from the Enforcement Directorate is not a real officer.", "The Supreme Court never calls people.",
    "It appears to be a genuine request from your bank.", "This is completely normal for a phone.",
    "Legitimate shops are unlikely to ask for this, so be careful.", "This is a scam!", "Is this a scam?",
    "Don't share it, and never pay a fee.", "The NPCI and CERT-In warn about such messages.",
    "Scammers use www.example-pay.in to steal money.", "Call +91 98765 43210 to complete KYC.",
    "The message was sent from 10-digit number 1234567890.", "Banks update KYC only at a branch, i.e. never by SMS.",
    "Your account will be blocked in 2 hours, it says.", "Always check the sender before you click.",
    " ".join(["This long sentence keeps adding words"] * 9) + ".", "this sentence starts in lower case.",
    "Here is the explanation: this message pretends to be from your bank.",
]
EXTRA_HI = [
    "यह संदेश सुरक्षित है।", "कॉल करें ९८७६५४३२१० पर।", "असली बैंक कभी OTP नहीं माँगते।",
    "यह एक घोटाला है और ठग आपका पैसा चाहता है।", "यह असली है, चिंता न करें।", "शिकायत cybercrime.gov.in पर करें।",
    "SBI के नाम पर २ लाख रुपये माँगे गए हैं।", "यह लिंक https://sbi-kyc.top/a पर ले जाता है।",
    "ठग आपको डराकर जल्दी पैसे भेजने को कहता है", "यह धोखाधड़ी नहीं है।",
]


def make_answers(a):
    from advisor import prompt as P
    cases = []                                     # (verdict, language, evidence, answer)
    for ex in P.EXAMPLES:
        case = P.format_case(ex["result"], ex["scam_type"], ex["pretends"], ex["signs"], ex["fact"], ex["wants"])
        verdict = "dangerous" if ex["result"] == P.RESULT_TEXT["dangerous"] else "suspicious"
        for lang in ("en", "hi"):
            cases.append((verdict, lang, case, ex["answer"][lang]))
    if a.graded:
        with open(a.graded, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r.get("answer") and r.get("case"):
                    cases.append((r["verdict"], r.get("language", "en"), r["case"], r["answer"]))
    rng = random.Random(44)
    rows = []

    def add(raw, verdict, language, evidence):
        rows.append({"raw": raw, "verdict": verdict, "language": language, "evidence": evidence})

    for verdict, lang, case, ans in cases:
        extra = EXTRA_HI + EXTRA_EN[:6] if lang == "hi" else EXTRA_EN
        for v in ("suspicious", "dangerous", "safe"):
            add(ans, v, lang, case)
        add(ans, verdict, lang, None)
        add(ans, verdict, "hi" if lang == "en" else "en", case)
        add("Here is the explanation: " + ans + "<|eot_id|><|start_header_id|>user", verdict, lang, case)
        add("  \n" + ans.replace(". ", ".\n\n", 1) + "\t", verdict, lang, case)
        for cut in (0.3, 0.6, 0.9):
            add(ans[:int(len(ans) * cut)], verdict, lang, case)
        for e in extra:
            add(ans + " " + e, verdict, lang, case)
            add(e + " " + ans, verdict, lang, case)
        for _ in range(12):                          # two to four sentences, mixed
            parts = rng.sample([ans] + extra, rng.randint(2, 4))
            add(" ".join(parts), rng.choice(("suspicious", "dangerous")), lang, rng.choice((case, case, None)))
    for raw in ("", "   ", "<|eot_id|>", "Answer:", "This message", "A. B. C."):
        add(raw, "dangerous", "en", "")
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{len(rows):,} answers from {len(cases)} cases -> {a.out}")


def compare_answers(a):
    from advisor.validator import check_explanation
    with open(a.answers, encoding="utf-8") as f:
        rows = [json.loads(x) for x in f]
    with open(a.phone, encoding="utf-8") as f:
        phone = [json.loads(x) for x in f]
    if len(rows) != len(phone):
        sys.exit(f"{len(rows)} answers but {len(phone)} from the phone")
    problems = []
    for r, ph in zip(rows, phone):
        c = check_explanation(r["raw"], r["verdict"], r["language"], evidence=r["evidence"])
        mine = {"what": c.what, "why": c.why, "ok": c.ok, "flags": c.flags}
        if mine != ph:
            problems.append((r, mine, ph))
    ok = sum(1 for r, ph in zip(rows, phone) if ph["ok"])
    print(f"{len(rows):,} answers: {len(rows) - len(problems):,} checked the same on the Pi and the phone "
          f"({ok:,} accepted, {len(rows) - ok:,} rejected by both)")
    for r, mine, ph in problems[:a.show]:
        print("\nraw  :", r["raw"][:200], f"[{r['verdict']}, {r['language']}]")
        for k in mine:
            if mine[k] != ph[k]:
                print(f"  {k}: Pi {mine[k]!r}\n  {' ' * len(k)}  phone {ph[k]!r}")
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
    m = sub.add_parser("answers")
    m.add_argument("--graded", help="Llama's answers from the Pi (JSONL with case and answer)")
    m.add_argument("--out", required=True)
    c = sub.add_parser("compare-answers")
    c.add_argument("--answers", required=True)
    c.add_argument("--phone", required=True)
    c.add_argument("--show", type=int, default=15)
    a = ap.parse_args(argv)
    if a.cmd == "inputs":
        make_inputs(a)
        return 0
    if a.cmd == "answers":
        make_answers(a)
        return 0
    if a.cmd == "compare-answers":
        return compare_answers(a)
    return compare(a)


if __name__ == "__main__":
    sys.exit(main())

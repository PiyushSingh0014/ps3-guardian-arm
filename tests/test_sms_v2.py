"""SMS model v2: the labeller, the measurement from the labels, the training and comparison
(detectors/sms/train_v2.py) and the app loading the model. Every message here is made up."""
import csv
import json
import os
import re
import sys

import joblib
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "detectors", "sms"))

import sms_traffic  # noqa: E402
import train_baseline as tb  # noqa: E402
import train_v2  # noqa: E402
from detectors.sms import detector as det  # noqa: E402


def write_log(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def entry(i, text, device="B", sender="JD-HDFCBK-T", kind="business", verdict="suspicious"):
    return {"id": i, "time": "2026-11-12 10:00:00", "device": device, "channel": "sms", "app": None,
            "sender": sender, "sender_kind": kind, "verdict": verdict, "score": 0.6, "category": "x",
            "text_verdict": verdict, "text_score": 0.6, "language": "en", "reasons": [],
            "text": None if text is None else re.sub(r"\d", "#", text)}          # as app/sms_log.py keeps it


# --- digits and the score the decision starts from ---------------------------------------------

def test_masked_digits_are_filled_the_same_way_every_time():
    masked = "OTP ###### for Rs.#,###.## at ##:##"
    filled = train_v2.fill_digits(masked, "e1")
    assert re.fullmatch(r"OTP \d{6} for Rs\.\d,\d{3}\.\d{2} at \d{2}:\d{2}", filled)
    assert train_v2.fill_digits(masked, "e1") == filled != train_v2.fill_digits(masked, "e2")
    assert train_v2.key("Your  OTP is 123456") == train_v2.key("your otp is ######")      # copies
    assert train_v2.key("राशि ₹१२०") == train_v2.key("राशि ₹###")                # Devanagari digits too


def test_marketing_is_trusted_only_from_a_registered_sender_id():
    p_fraud, p_normal = 0.2, 0.1                 # a text that reads like an offer (marketing 0.7)
    assert det.model_score(p_fraud, p_normal, "VM-CROMAS-P") == pytest.approx(0.2)
    for sender in ("9812345678", "+91 98123 45678", None, "", "Rahul", "AIRTEL BANK"):
        assert det.model_score(p_fraud, p_normal, sender) == pytest.approx(0.9)
    for sender in ("JD-HDFCBK-S", "9812345678", None):                  # v1: one number, unchanged
        assert det.model_score(0.83, 1 - 0.83, sender) == pytest.approx(0.83)


def test_near_copies_of_test_messages_are_found():
    import pandas as pd
    test = pd.DataFrame({"key": [train_v2.key("483920 is your OTP for login to Swiggy. Valid for 10 minutes.")]})
    df = pd.DataFrame({"key": [train_v2.key(t) for t in (
        "112233 is your OTP for login to Zomato. Valid for 5 minutes.",          # same template
        "Dear customer, your Amazon order has been shipped and arrives tomorrow.",
        "483920 is your OTP for login to Swiggy. Valid for 10 minutes.")]})      # a copy
    assert train_v2.near_copies(df, test).tolist() == [True, False, True]
    assert not train_v2.near_copies(df, test.iloc[0:0]).any()


# --- labelling and measuring -------------------------------------------------------------------

@pytest.fixture
def log(tmp_path):
    path = tmp_path / "sms.jsonl"
    write_log(path, [entry("e1", "Your OTP is 123456. Do not share it."),
                     entry("e2", "Your OTP is 654321. Do not share it."),        # the same, digits aside
                     entry("e3", "You won a prize, call now", sender="mobile", kind="mobile"),
                     entry("e4", None, sender="mobile", kind="mobile", verdict="safe"),   # text not kept
                     entry("e5", "Flat 50% off this weekend", device="C", sender="VM-CROMAS-P")])
    return path


def test_label_asks_each_message_once_and_can_undo(log, tmp_path):
    labels = tmp_path / "labels.json"
    said = []
    answers = iter(["n", "x", "u", "n", "f"])        # normal, a typo, undo, normal again, fraud
    sms_traffic.label(str(log), str(labels), device="B", ask=lambda _: next(answers), say=said.append)
    assert json.loads(labels.read_text()) == {"e1": "ham", "e2": "ham", "e3": "smishing"}
    assert "Messages left to label, by phone: B 3, C 1" in said          # e4 has no text
    assert "Now: 2 messages to label (3 with their copies).\n" in said
    assert not any("Flat 50%" in s for s in said)                       # phone C's message is not shown
    assert not any("SUSPICIOUS" in s.upper() or "0.6" in s for s in said if "phone B" in s)   # labelled blind
    said.clear()
    sms_traffic.label(str(log), str(labels), device="B", ask=lambda _: pytest.fail("asked again"),
                      say=said.append)
    assert "Nothing left to label on phone B" in said[0]
    sms_traffic.label(str(log), str(labels), device="C", ask=lambda _: "q", say=said.append)
    assert json.loads(labels.read_text()) == {"e1": "ham", "e2": "ham", "e3": "smishing"}
    said.clear()
    assert sms_traffic.label(str(log), str(labels), device="b", say=said.append) == 1
    assert said == ["No messages with text from phone b. Phones in the log: B, C (the names are case-sensitive; "
                    "- is a phone without a name)."]


def test_label_only_the_flagged_messages(log, tmp_path, monkeypatch):
    labels, said = tmp_path / "labels.json", []
    write_log(log, [entry("s1", "Your OTP is 123456", verdict="safe"),
                    entry("s2", "Win a prize, call now", sender="mobile", kind="mobile"),
                    entry("s3", "Flat 50% off", device="C", sender="VM-CROMAS-P")])
    seen = {}
    monkeypatch.setattr(sms_traffic, "label", lambda *a, **k: seen.update(k) or 0)
    sms_traffic.main(["label", "--flagged", "--log", str(log), "--labels", str(labels)])
    assert seen == {"flagged": True}
    monkeypatch.undo()
    answers = iter(["f", "m"])
    sms_traffic.label(str(log), str(labels), flagged=True, ask=lambda _: next(answers), say=said.append)
    assert said[0] == "Flagged messages left to label, by phone: B 1, C 1"
    assert json.loads(labels.read_text()) == {"s2": "smishing", "s3": "spam"}              # the OTP is not asked


def test_labels_from_excel_can_be_imported(log, tmp_path, capsys):
    labels, sheet = tmp_path / "labels.json", tmp_path / "traffic.csv"
    labels.write_text(json.dumps({"e5": "spam"}))
    sms_traffic.export(str(log), str(sheet), str(labels))
    with open(sheet, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert [r["label"] for r in rows] == ["", "", "", "", "spam"]       # labels made on the Pi come along
    rows[0]["label"], rows[2]["label"], rows[3]["label"] = "ham", " Smishing ", "maybe"
    with open(sheet, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    assert sms_traffic.main(["import", str(sheet), "--labels", str(labels)]) == 0
    assert json.loads(labels.read_text()) == {"e1": "ham", "e3": "smishing", "e5": "spam"}
    assert "Imported 3 labels" in capsys.readouterr().out


def test_measure_reads_the_labels(log, tmp_path, capsys):
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"e1": "ham", "e3": "smishing", "e5": "spam"}))
    assert sms_traffic.main(["measure", "--log", str(log), "--labels", str(labels)]) == 0
    out = capsys.readouterr().out
    assert "5 messages, 3 labelled; 1 without text" in out
    assert "Labelled, by phone: B 2, C 1" in out and "Received, by phone: B 4, C 1" in out
    rows = {line[:44].strip(): line[44:].split() for line in out.splitlines()
            if line.startswith(("SMS from", "all "))}
    # received, flagged, flagged and labelled fraud / marketing / normal, not labelled, missed scams, per 100
    assert rows["SMS from a registered sender ID"] == ["3", "3", "0", "1", "1", "1", "0", "33.3"]
    assert rows["SMS from a phone number"] == ["2", "1", "1", "0", "0", "0", "-", "0.0"]
    assert rows["all"] == ["5", "4", "1", "1", "1", "1", "20.0"]


def test_review_asks_again_about_likely_wrong_labels(tmp_path):
    path, labels = tmp_path / "sms.jsonl", tmp_path / "labels.json"
    write_log(path, [entry("r1", "SBI Carnival: up to 5X points on spends", sender="VK-SBIBNK-P"),
                     entry("r2", "Your OTP is 123456", device="B", sender="AX-SFGOLD-T"),
                     entry("r3", "Your OTP is 654321", device="C", sender="AX-SFGOLD-T"),
                     entry("r4", "Win Rs 5 lakh, pay the fee now", sender="mobile", kind="mobile"),
                     entry("r5", "KYC pending, update at http://kyc.example", sender="AD-SBIKYC-S")])
    labels.write_text(json.dumps({"r1": "smishing", "r2": "ham", "r3": "smishing", "r4": "smishing",
                                  "r5": "smishing"}))
    said, answers = [], iter(["m", "n", "u", "", "q"])     # change, change, undo it, keep, stop
    assert sms_traffic.review(str(path), str(labels), ask=lambda _: next(answers), say=said.append) == 0
    assert "3 labels to look at again (4 with their copies)." in said
    assert json.loads(labels.read_text()) == {"r1": "spam", "r2": "ham", "r3": "smishing", "r4": "smishing",
                                              "r5": "smishing"}
    notes = [s for s in said if s.startswith("    -> ")]
    assert notes[0] == "    -> labelled fraud, but it came from a registered sender ID"
    assert notes[1].startswith("    -> labelled two ways: fraud and normal (copies also: AX-SFGOLD-T, C)")
    assert not any("0.6" in s for s in said)                                        # asked blind
    labels.write_text(json.dumps({"r4": "smishing"}))
    said.clear()
    sms_traffic.review(str(path), str(labels), ask=lambda _: pytest.fail("asked"), say=said.append)
    assert said[0].startswith("Nothing to review")


# --- training and comparing --------------------------------------------------------------------

NORMAL = ["ok see you at the {} cafe tonight", "can you call me after the {} class", "reached home, dinner with {}",
          "the meeting moved to the {} room", "happy birthday! party at {} house", "bring the notes for {}"]
MARKETING = ["Flat 50% off on all {} shoes this weekend at our store", "Buy 1 get 1 free on {} pizzas, order now",
             "New {} plans with extra data, recharge in the app"]
FRAUD = ["Your account will be blocked today, update KYC at http://kyc-{}.example now",
         "You won a {} lottery prize, pay the fee to claim it",
         "Your parcel is held, pay the fee at http://post-{}.example/pay today"]


def word(i):
    """A different word for each i, without digits (digits all read as 7, so they make no copies)."""
    w = ""
    while True:
        w, i = chr(97 + i % 26) + w, i // 26 - 1
        if i < 0:
            return "z" + w


def fill(templates, n, start=0):
    return [templates[i % len(templates)].format(word(start + i)) for i in range(n)]


@pytest.fixture
def data(tmp_path):
    public = tmp_path / "merged.csv"
    rows = [("ham", t, "mishra_soni") for t in fill(NORMAL, 40)]
    rows += [("spam", t, "mishra_soni") for t in fill(MARKETING, 12)]
    rows += [("smishing", t, "mishra_soni") for t in fill(FRAUD, 12)]
    rows += [("spam", FRAUD[0].format(word(0)), "uci"),     # UCI spam that Mishra & Soni call smishing
             ("spam", "Txt WIN to 80086 for a free ringtone", "uci"),          # UCI only: left out
             ("ham", NORMAL[0].format(word(0)), "uci"),
             ("ham", "is this a scam? call me", "mishra_soni"), ("smishing", "is this a scam? call me", "uci")]
    with open(public, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "message", "source"])
        w.writerows(rows)
    log, labels = [], {}
    for device, at in (("B", 1000), ("C", 2000)):
        for lab, texts, sender, kind in (
                ("ham", fill(["Rs 250 debited from your account to {} via UPI. Not you? Call the bank"], 8, at),
                 "JD-HDFCBK-T", "business"),
                ("spam", fill(["Get 2GB extra data with the {} pack, offer till 30 Nov"], 4, at), "VM-JIOINF-P", "business"),
                ("smishing", fill(FRAUD, 3, at + 500), "mobile", "mobile")):
            for t in texts:
                log.append(entry(f"t{len(log)}", t, device=device, sender=sender, kind=kind))
                labels[log[-1]["id"]] = lab
    log.append(entry("t999", "Your OTP 4839 for Swiggy login is valid for 10 minutes", device="C"))
    labels["t999"] = "ham"                                       # a near-copy of an India test message
    write_log(tmp_path / "sms.jsonl", log)
    (tmp_path / "labels.json").write_text(json.dumps(labels))
    india = tmp_path / "india.csv"
    with open(india, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "message", "sender"])
        w.writerows([("smishing", "Electricity will be cut tonight, call the officer on this number now", "9800011111"),
                     ("spam", "Mega sale on televisions, visit the showroom", "VM-TVSALE-P"),
                     ("ham", "Your OTP 1234 for Zomato login is valid for 5 minutes", "AD-ZOMATO-S")])
    return tmp_path


def test_train_compare_and_save(data, capsys):
    out = data / "sms_v2.joblib"
    assert train_v2.main(["--public", str(data / "merged.csv"), "--log", str(data / "sms.jsonl"),
                          "--labels", str(data / "labels.json"), "--india", str(data / "india.csv"),
                          "--no-links", "--save", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "left out: 1 UCI-only spam, 1 labelled two ways" in text
    assert "Team:   30 different labelled messages" in text and "1 in the India set or near-copies" in text
    for title in ("Team messages held out", "India test set: 3 messages", "Public messages held out",
                  "Phone B: 15 messages", "Phone C: 15 messages", "Saved SMS model v2",
                  "SMS from sender IDs (every text is kept):",
                  "Phone numbers and chats (kept only when v1 flagged them):",
                  "Rule (docs/sms-model-v2.md, step 5), as the app decides:"):
        assert title in text
    assert "  India set: scams caught v1 " in text and "  Phone B, SMS from sender IDs: " in text

    bundle = joblib.load(out)
    assert bundle["version"] == 2 and set(bundle["classes"]) == {"fraud", "marketing", "normal"}
    d = det.SmsDetector(model_path=str(out), url_detector=None)
    assert d.model_name == "v2 (sms_v2.joblib)"
    msg = "Get 5GB extra data on recharge, offer till 30 Nov"
    p_fraud, p_normal = d.text_probs(msg)
    assert d.text_score(msg, "VM-JIOINF-P") == pytest.approx(p_fraud)
    assert d.text_score(msg, "9812345678") == pytest.approx(1 - p_normal)
    f = d.check("Your account will be blocked today, update KYC at http://kyc-9.example now", sender="9812345678")
    assert f.verdict != "safe"


def test_the_rule_for_using_v2(capsys):
    india = {"v1": {("", "fraud"): (100, 96)}, "v2": {("", "fraud"): (100, 94)}}
    def phone(alarms1, alarms2, caught1=1, caught2=1):
        return {"v1": {("always", "normal"): (10, alarms1), ("always", "fraud"): (2, caught1),
                       ("flagged", "fraud"): (5, 5)},
                "v2": {("always", "normal"): (10, alarms2), ("always", "fraud"): (2, caught2),
                       ("flagged", "fraud"): (5, 1)}}          # phone numbers: not part of the rule
    assert train_v2.rule(india, {"B": phone(3, 1), "C": phone(2, 2)})          # fewer in all, worse nowhere
    assert not train_v2.rule(india, {"B": phone(3, 1), "C": phone(2, 3)})      # worse on phone C
    assert not train_v2.rule(india, {"B": phone(3, 1, caught2=0)})             # a scam missed
    assert not train_v2.rule(india, {"B": phone(2, 2)})                        # no fewer false alarms
    worse = {"v1": india["v1"], "v2": {("", "fraud"): (100, 93)}}
    assert not train_v2.rule(worse, {"B": phone(3, 1)})                        # 3 more scams missed
    assert not train_v2.rule(None, {"B": phone(3, 1)})                         # India set needed
    assert "-> v2 does not pass: the app keeps v1" in capsys.readouterr().out


def test_the_app_prefers_v2_when_it_has_been_trained(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDIAN_SMS_MODEL")
    monkeypatch.setattr(det, "V2_MODEL", str(tmp_path / "sms_v2.joblib"))
    assert det.default_model() == tb.MODEL                     # not trained here: v1
    (tmp_path / "sms_v2.joblib").write_bytes(b"")
    assert det.default_model() == str(tmp_path / "sms_v2.joblib")
    monkeypatch.setenv("GUARDIAN_SMS_MODEL", "/elsewhere/model.joblib")
    assert det.default_model() == "/elsewhere/model.joblib"

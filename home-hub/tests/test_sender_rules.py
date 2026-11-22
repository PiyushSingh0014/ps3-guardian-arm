"""Update 37: the sender rules from the hard review (suffix, cap, brand), the request-for-a-secret
signal they use, the file that switches them on, and the measurement that decides which go live.
Every message here is made up."""
import csv
import json
import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detectors", "sms"))

import senders  # noqa: E402
from detectors.sms import detector as det  # noqa: E402
from rules_india import asks_for_secret  # noqa: E402
from tests.auth import client  # noqa: E402

KYC = "Your SBI account will be blocked today. Update your KYC at http://sbi-kyc-ps3lab.xyz/login"
SHARE = "Dear customer, share the OTP sent to you with our officer to stop the block on your SBI account"


def verdict(score, text, sender, rules, links=None):
    return det.decide(score, text, sender, links=links, rules=rules)


# --- the signal ---------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [SHARE, "send your OTP to 9812345678 to receive the refund",
                                  "Enter your UPI PIN to receive Rs 5000", "Please reply with your card number"])
def test_requests_for_a_secret(text):
    assert asks_for_secret(text)


@pytest.mark.parametrize("text", ["Your OTP is 482913. Do not share it with anyone.", "Enter OTP 482913 to log in",
                                  "Never share your PIN or password", "SBI never asks you to share your OTP"])
def test_genuine_otp_wording_is_no_request(text):
    assert not asks_for_secret(text)


# --- the rules ----------------------------------------------------------------------------------

def test_a_header_without_a_suffix_is_trusted_less():
    text = "Your parcel is waiting, pay the fee today"
    assert verdict(0.9, text, "AD-HDFCBK", set())[1] == "safe"                   # odds 9 x 0.1 -> 0.47
    score, v, _ = verdict(0.9, text, "AD-HDFCBK", {"suffix"})                    # odds 9 x 0.3 -> 0.73
    assert v == "suspicious" and score == pytest.approx(0.73, abs=0.01)
    assert verdict(0.9, text, "AD-HDFCBK-S", {"suffix"})[1] == "safe"            # a suffix: as before


def test_a_risky_message_naming_a_brand_needs_the_brands_sender_id():
    score, v, sig = verdict(0.9, KYC, "AD-QWERTY-S", {"brand"})
    assert v == "dangerous" and sig.reasons[0] == "names SBI, but its sender ID does not look like one of SBI's"
    assert verdict(0.9, KYC, "AD-SBIINB-S", {"brand"})[1] == "safe"              # SBI's own: the discount stays
    assert verdict(0.9, KYC, "AD-QWERTY-S", set())[1] == "safe"                  # the rule switched off
    card = "Your Airtel Axis Bank credit card is blocked, call us"                # co-branded: Airtel's own ID
    assert verdict(0.9, card, "AE-AIRTEL-S", {"brand"})[1] == "safe"
    offer = "Get 10% off with HDFC Bank cards at our store this weekend"         # names a bank, claims nothing
    assert verdict(0.9, offer, "VM-SHOPPY-P", {"brand"})[1] != "dangerous"
    assert det.brand_mismatch(offer, senders.classify_sender("VM-SHOPPY-P")) is None
    assert det.brand_mismatch("Your Union Bank account is blocked", senders.classify_sender("AD-QWERTY-S")) is None


def test_no_sender_id_clears_a_request_for_a_secret():
    score, v, sig = verdict(0.9, SHARE, "VM-SBIINB-S", {"cap"})
    assert v == "suspicious" and score == 0.5 and sig.reasons[0].startswith("asks you to share or enter an OTP")
    assert verdict(0.9, SHARE, "VM-SBIINB-S", set())[1] == "safe"
    assert verdict(0.4, SHARE, "VM-SBIINB-S", {"cap"})[1] == "safe"              # the text itself is not suspicious
    unsafe = [SimpleNamespace(verdict="suspicious", official=False, reasons=[], score=0.6, kind="site", decisive=False)]
    text = "SBI: your account statement is ready, see the link"
    assert verdict(0.9, text, "VM-SBIINB-S", {"cap"}, links=unsafe)[1] == "suspicious"
    assert verdict(0.9, text, "VM-SBIINB-S", {"cap"})[1] == "safe"               # no link: nothing to cap


def test_rules_come_from_the_file(tmp_path):
    path = tmp_path / "rules.json"
    assert senders.active_rules(str(path)) == frozenset()                       # no file: none, as before
    path.write_text(json.dumps({"rules": ["cap", "nonsense"]}))
    assert senders.active_rules(str(path)) == {"cap"}
    path.write_text(json.dumps({"rules": ["cap", "suffix"]}))
    os.utime(path, (1, 1))
    assert senders.active_rules(str(path)) == {"cap", "suffix"}
    path.write_text("not json")
    os.utime(path, (2, 2))
    assert senders.active_rules(str(path)) == frozenset()


def test_health_lists_the_rules_switched_on(tmp_path, monkeypatch):
    from advisor.advise import Advisor
    from app.server import create_app
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": ["suffix"]}))
    monkeypatch.setenv("GUARDIAN_SENDER_RULES", str(path))
    app = create_app(detector=det.SmsDetector(url_detector=None), advisor=Advisor(),
                     net_alerts=str(tmp_path / "a.jsonl"), net_explain_every_s=None)
    assert client(app).get("/health").json()["sender_rules"] == ["suffix"]


# --- the measurement ----------------------------------------------------------------------------

def test_the_measurement_switches_on_only_the_rules_that_add_no_false_alarm(tmp_path, monkeypatch, capsys):
    import eval_senders
    # The model's chance of fraud, fixed per message so the test does not depend on the sample model.
    monkeypatch.setattr(eval_senders.SmsDetector, "text_probs",          # the class the script uses
                        lambda self, m: (0.9, 0.1) if "SCAMMY" in m else (0.2, 0.8))
    log = [  # a genuine notice from a header without a suffix: only the suffix rule flags it
        {"id": "a1", "sender": "AD-HDFCBK", "sender_kind": "business", "text": "SCAMMY your card bill is ready"},
        # a scam from a registered ID asking for the OTP: the cap rule catches it
        {"id": "a2", "sender": "VM-SBIINB-S", "sender_kind": "business", "text": "SCAMMY " + SHARE},
        {"id": "a3", "sender": "VM-SHOPPY-P", "sender_kind": "business", "text": "Flat 50% off this weekend"},
        {"id": "a4", "sender": "mobile", "sender_kind": "mobile", "text": "SCAMMY call me"},     # not from an ID
        {"id": "a5", "sender": "VM-SHOPPY-P", "sender_kind": "business", "text": "New arrivals in store"}]
    (tmp_path / "log.jsonl").write_text("\n".join(json.dumps(e) for e in log) + "\n")
    (tmp_path / "labels.json").write_text(json.dumps({"a1": "ham", "a2": "smishing", "a3": "spam", "a4": "smishing"}))
    with open(tmp_path / "india.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "message", "sender"])
        w.writerows([("spam", "SCAMMY Mega sale on televisions", "VM-TVSALE-P"), ("ham", "Your OTP is 4821", "AD-ZOMATO-S"),
                     ("smishing", "SCAMMY KYC pending", "9800011111")])
    rules = tmp_path / "rules.json"
    assert eval_senders.main(["--india", str(tmp_path / "india.csv"), "--log", str(tmp_path / "log.jsonl"),
                              "--labels", str(tmp_path / "labels.json"), "--no-links", "--apply", "--show",
                              "--rules-file", str(rules)]) == 0
    out = capsys.readouterr().out
    assert "India set 2" in out and "team 4 different" in out
    assert "suffix  does not pass: +1 genuine flagged" in out
    assert "cap     passes: +0 genuine flagged, +1 scams caught" in out
    assert json.loads(rules.read_text())["rules"] == ["cap", "brand"]
    assert senders.active_rules(str(rules)) == {"cap", "brand"}
    assert "suffix  team  normal" in out                                        # --show lists what changed

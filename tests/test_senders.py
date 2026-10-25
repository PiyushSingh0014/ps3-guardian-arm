"""Sender-aware scoring (detectors/sms/senders.py) and its use in the detector's decision."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detectors", "sms"))
from rules_india import extract_signals  # noqa: E402
from senders import apply_sender, classify_sender  # noqa: E402

from detectors.sms.detector import decide, sender_type  # noqa: E402


@pytest.mark.parametrize("raw, kind, suffix", [
    ("JD-HDFCBK-S", "business", "S"),
    ("ax-sbiinb-t", "business", "T"),
    ("VM-AIRTEL-P", "business", "P"),
    ("CP-TRAIND-G", "business", "G"),
    ("AD-HDFCBK", "business", ""),
    ("HDFCBK", "business", ""),
    ("TM-612345", "business", ""),          # numeric promotional header
    ("+91 98123 45678", "mobile", ""),
    ("09812345678", "mobile", ""),
    ("9812345678", "mobile", ""),
    ("612345", "other", ""),                # bare six digits: a short code
    ("1909", "other", ""),
    ("HDFC Bank", "other", ""),             # a name typed by hand is not evidence
    ("", "unknown", ""),
    (None, "unknown", ""),
])
def test_classify_sender(raw, kind, suffix):
    info = classify_sender(raw)
    assert (info.kind, info.suffix) == (kind, suffix)


def test_sender_type_names():
    assert sender_type("+91 98123 45678") == "mobile_number"
    assert sender_type("JD-HDFCBK-S") == "registered_sender_id"
    assert sender_type("HDFC Bank") == "other" and sender_type(None) == "unknown"


OTP = "123456 is your OTP for login. Do not share it with anyone."
SCAM = "Dear customer your SBI account will be blocked today, update KYC: http://sbi-kyc.example/u"
CHAT = "ok see you at 6"


def test_registered_service_header_clears_a_text_false_alarm():
    sig = extract_signals(OTP)
    assert apply_sender(0.98, classify_sender("JD-HDFCBK-S"), sig) < 0.5
    assert apply_sender(0.98, classify_sender("VM-SHOPKT-P"), sig) > 0.8   # promotional: weaker


def test_mobile_number_raises_risky_messages_only():
    risky, plain = extract_signals(SCAM), extract_signals(CHAT)
    assert apply_sender(0.40, classify_sender("9812345678"), risky) > 0.7
    assert apply_sender(0.40, classify_sender("9812345678"), plain) == 0.40
    assert apply_sender(0.40, classify_sender("HDFC Bank"), risky) == 0.40   # unknown kind: no change


def test_apk_link_stays_dangerous_whoever_sends_it():
    msg = "Update your KYC: install http://kyc-update.example/sbi.apk"
    score, verdict, _ = decide(0.30, msg, sender="JD-SBIINB-S")
    assert verdict == "dangerous" and score >= 0.95


def test_use_sender_false_is_the_text_only_decision():
    assert decide(0.98, OTP, sender="JD-HDFCBK-S", use_sender=False)[1] == "dangerous"
    assert decide(0.98, OTP, sender="JD-HDFCBK-S")[1] == "safe"

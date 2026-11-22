"""scripts/accuracy_test.py: the intervals, the Indian scam reports and the title check (update 49)."""
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import accuracy_test as at  # noqa: E402


def test_wilson_interval():
    assert at.wilson(0, 0) == (0.0, 0.0)
    lo, hi = at.wilson(96, 100)
    assert 90 < lo < 91 and 98 < hi < 99
    assert at.share(1, 4).startswith("1 of 4 (25.0%")


def test_reports_india_only_one_per_campaign_and_placeholders_back(tmp_path):
    p = tmp_path / "reports.csv"
    rows = [("IND", "Dear customer your SBI account will be blocked today, update KYC <URL>", "banking"),
            ("IND", "Dear customer your SBI account will be blocked today, update KYC now <URL>", "banking"),
            ("IND", "Dear customer your SBI account will be blocked today, update KYC <URL>", "banking"),
            ("IND", "Call <PHONE_NUMBER> on <DATE_TIME>, <NAMED_ENTITY> from customs has your parcel", "delivery"),
            ("USA", "Your package is waiting <URL>", "delivery"),
            ("IND", "Win a free iPhone today, claim at <URL>", "others")]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["original_network_country", "text", "scam_type"])
        w.writerows(rows)
    picked, info = at.smishing_messages(str(p), avoid=["WIN a free iPhone today, claim at"])
    assert info == {"reports": 5, "different": 4, "like_known": 1, "campaigns": 2}
    kyc, parcel = picked
    assert kyc["reports"] == 3 and kyc["text"].endswith("http://link.example/x")
    assert parcel["text"] == "Call 9812345678 on 22/11/2026, Rahul from customs has your parcel"
    assert parcel["type"] == "delivery"


def test_titles_right_general_wrong():
    res = [{"label": "scam", "verdict": "dangerous", "type": "bank_kyc", "category": "bank_kyc_scam"},
           {"label": "scam", "verdict": "suspicious", "type": "lottery_reward", "category": "generic_suspicious"},
           {"label": "scam", "verdict": "dangerous", "type": "lottery_reward", "category": "bank_kyc_scam"},
           {"label": "scam", "verdict": "dangerous", "type": "loan_app", "category": "generic_suspicious"},
           {"label": "scam", "verdict": "safe", "type": "bank_kyc", "category": "promo_spam"}]     # missed: not counted
    right, general, wrong, pairs = at.titles(res)
    assert (right, general, wrong) == (2, 1, 1)
    assert pairs == {("lottery_reward", "bank_kyc_scam"): 1}

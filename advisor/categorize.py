"""Maps a flagged message to a playbook key.

A rule-based stopgap. Replace it with the scam-type head of your trained
message classifier in weeks 3-5; keep the same keys so playbooks still match.
Order matters: the most severe patterns are checked first.
"""
import re

_RULES = [
    ("apk_malware_link",
     lambda m, s: s.has_apk),
    ("digital_arrest_scam",
     lambda m, s: re.search(r"\b(digital arrest|cbi|narcotics|police|arrest warrant|"
                            r"customs officer|court case|money laundering)\b", m, re.I)),
    ("delivery_fee_scam",
     lambda m, s: re.search(r"\b(parcel|courier|shipment|delivery|customs|redeliver)\b", m, re.I)),
    ("job_task_scam",
     lambda m, s: re.search(r"\b(work from home|part[- ]time|job offer|daily earning|"
                            r"earn rs|selected for a)\b", m, re.I)),
    ("lottery_reward_scam",
     lambda m, s: s.reward_bait),
    ("utility_disconnection_scam",
     lambda m, s: re.search(r"\b(electricity|power supply|light bill|disconnect\w*)\b", m, re.I)),
    ("otp_theft",
     lambda m, s: s.asks_secret and not s.bank_context),
    ("bank_kyc_scam",
     lambda m, s: s.bank_context),
]


def categorize_message(message, signals):
    m = message or ""
    for key, rule in _RULES:
        if rule(m, signals):
            return key
    risky = any([signals.has_url, signals.has_apk, signals.asks_secret, signals.has_upi,
                 signals.urgency, signals.bank_context, signals.reward_bait])
    return "generic_suspicious" if risky else "promo_spam"

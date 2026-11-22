"""Maps a flagged message to a playbook key.

A rule-based stopgap. Replace it with the scam-type head of your trained
message classifier in weeks 3-5; keep the same keys so playbooks still match.
Order matters: the most severe patterns are checked first.
"""
import re

# Module-level so that scripts/export_phone_guard.py can copy them to the phone app.
DIGITAL_ARREST_RE = re.compile(r"\b(digital arrest|cbi|narcotics|police|arrest warrant|"
                               r"customs officer|court case|money laundering)\b", re.I)
DELIVERY_RE = re.compile(r"\b(parcel|courier|shipment|delivery|customs|redeliver)\b", re.I)
JOB_RE = re.compile(r"\b(work from home|part[- ]time|job offer|daily earning|earn rs|selected for a)\b", re.I)
UTILITY_RE = re.compile(r"\b(electricity|power supply|light bill|disconnect\w*)\b", re.I)

_RULES = [
    ("apk_malware_link",
     lambda m, s: s.has_apk),
    ("digital_arrest_scam",
     lambda m, s: DIGITAL_ARREST_RE.search(m)),
    ("delivery_fee_scam",
     lambda m, s: DELIVERY_RE.search(m)),
    ("job_task_scam",
     lambda m, s: JOB_RE.search(m)),
    ("lottery_reward_scam",
     lambda m, s: s.reward_bait),
    ("utility_disconnection_scam",
     lambda m, s: UTILITY_RE.search(m)),
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

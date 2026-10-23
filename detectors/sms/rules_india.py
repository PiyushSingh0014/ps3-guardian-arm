"""India-focused red-flag signals for scam / smishing detection.

Pure, dependency-free functions. Each message is reduced to:
  - a small numeric feature vector (fed to the ML model), and
  - a list of human-readable reasons (the seed for the Llama advisor's "why").

Nothing here is operational. It only READS a message and flags known patterns,
so it is safe to run on anything.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

# --- patterns -------------------------------------------------------------
URL_RE          = re.compile(r'(https?://|www\.)\S+', re.I)
BARE_DOMAIN_RE  = re.compile(r'\b([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?', re.I)
APK_RE          = re.compile(r'\.apk\b', re.I)
UPI_RE          = re.compile(r'\b[\w.-]+@(oksbi|okhdfcbank|okaxis|okicici|ybl|paytm|upi|apl|example)\b', re.I)
SECRET_RE       = re.compile(r'\b(otp|one[\s-]?time[\s-]?password|cvv|\bpin\b|mpin|password|card number)\b', re.I)
URGENCY_RE      = re.compile(r'\b(urgent|immediately|act now|verify now|last chance|within\s+\d+\s*(min|hour|hr|hrs)|today|blocked|suspend|disconnect|expire)\b', re.I)
MONEY_RE        = re.compile(r'(₹|\brs\.?\b|\binr\b)\s?\d', re.I)
SHORTENER_RE    = re.compile(r'\b(bit\.ly|tinyurl|t\.co|rb\.gy|cutt\.ly|is\.gd|short\.\w+|\.link/)\b', re.I)
BANK_WORDS_RE   = re.compile(r'\b(bank|sbi|hdfc|icici|axis|kotak|pnb|rbi|netbanking|debit|credit\s?card|kyc|account)\b', re.I)
REWARD_RE       = re.compile(r'\b(congratulations|you.?ve won|lottery|prize|cashback|refund|lucky winner|claim your)\b', re.I)
TEN_DIGIT_RE    = re.compile(r'^[6-9]\d{9}$')

# RBI's exclusive bank domain (migration completed 31 Oct 2025).
BANK_IN_RE      = re.compile(r'\b[a-z0-9-]+\.bank\.in\b', re.I)
# TRAI DLT header suffixes for registered commercial senders (-P/-S/-T/-G).
TRAI_SUFFIX_RE  = re.compile(r'-[PSTG]\b')

FEATURE_NAMES = [
    "has_url", "has_shortener", "has_apk", "asks_secret", "has_upi",
    "urgency", "mentions_money", "bank_context", "reward_bait",
    "bank_link_not_bankin", "sender_is_10_digit",
]


@dataclass
class Signals:
    has_url: int = 0
    has_shortener: int = 0
    has_apk: int = 0
    asks_secret: int = 0
    has_upi: int = 0
    urgency: int = 0
    mentions_money: int = 0
    bank_context: int = 0
    reward_bait: int = 0
    bank_link_not_bankin: int = 0
    sender_is_10_digit: int = 0
    reasons: list = field(default_factory=list)

    def vector(self):
        return [getattr(self, n) for n in FEATURE_NAMES]


def extract_signals(message: str, sender: Optional[str] = None) -> Signals:
    """Reduce one message (and optional sender ID) to a Signals object."""
    s = Signals()
    m = message or ""

    if URL_RE.search(m) or BARE_DOMAIN_RE.search(m):
        s.has_url = 1
        s.reasons.append("contains a link")
    if SHORTENER_RE.search(m):
        s.has_shortener = 1
        s.reasons.append("uses a link shortener that hides the real destination")
    if APK_RE.search(m):
        s.has_apk = 1
        s.reasons.append("asks you to install an .apk app from outside the Play Store")
    if SECRET_RE.search(m):
        s.asks_secret = 1
        s.reasons.append("mentions OTP / PIN / CVV / password")
    if UPI_RE.search(m):
        s.has_upi = 1
        s.reasons.append("contains a UPI ID")
    if URGENCY_RE.search(m):
        s.urgency = 1
        s.reasons.append("uses urgency or a threat of blocking / expiry")
    if MONEY_RE.search(m):
        s.mentions_money = 1
    if BANK_WORDS_RE.search(m):
        s.bank_context = 1
    if REWARD_RE.search(m):
        s.reward_bait = 1
        s.reasons.append("promises a prize, refund or cashback")

    # A "bank" message whose link is NOT on the official .bank.in domain.
    if s.bank_context and s.has_url and not BANK_IN_RE.search(m):
        s.bank_link_not_bankin = 1
        s.reasons.append("claims to be a bank but the link is not on an official .bank.in domain")

    if sender and TEN_DIGIT_RE.match(sender.strip()):
        s.sender_is_10_digit = 1
        if s.bank_context:
            s.reasons.append("a genuine bank never texts from a 10-digit mobile number")

    return s


if __name__ == "__main__":
    demo = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify"
    sig = extract_signals(demo, sender="9812345678")
    print("vector :", sig.vector())
    print("reasons:", sig.reasons)

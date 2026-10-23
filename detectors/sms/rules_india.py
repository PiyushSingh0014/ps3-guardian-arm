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
# "call / WhatsApp <Indian mobile number>": a reason only, not a model feature.
CALL_NUMBER_RE  = re.compile(r'\b(call|contact|whatsapp|dial)\b\D{0,25}(\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b', re.I)

# RBI's exclusive bank domain (migration completed 31 Oct 2025).
BANK_IN_RE      = re.compile(r'\b[a-z0-9-]+\.bank\.in\b', re.I)
# TRAI DLT header suffixes for registered commercial senders (-P/-S/-T/-G).
TRAI_SUFFIX_RE  = re.compile(r'-[PSTG]\b')


def normalize_sender(sender):
    """'+91 98123-45678' / '09812345678' -> '9812345678'; sender IDs are returned unchanged."""
    s = (sender or "").strip()
    digits = re.sub(r"[\s()-]", "", s).lstrip("+")
    if digits.isdigit():
        if len(digits) == 12 and digits.startswith("91"):
            return digits[2:]
        if len(digits) == 11 and digits.startswith("0"):
            return digits[1:]
        return digits
    return s

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
    """Reduce one message (and optional sender ID) to a Signals object.

    The feature vector is unchanged since v1, so saved models keep working.
    Reasons are listed most important first: the advisor passes the top few to
    Llama as the warning signs it explains.
    """
    s = Signals()
    m = message or ""

    s.has_url = int(bool(URL_RE.search(m) or BARE_DOMAIN_RE.search(m)))
    s.has_shortener = int(bool(SHORTENER_RE.search(m)))
    s.has_apk = int(bool(APK_RE.search(m)))
    s.asks_secret = int(bool(SECRET_RE.search(m)))
    s.has_upi = int(bool(UPI_RE.search(m)))
    s.urgency = int(bool(URGENCY_RE.search(m)))
    s.mentions_money = int(bool(MONEY_RE.search(m)))
    s.bank_context = int(bool(BANK_WORDS_RE.search(m)))
    s.reward_bait = int(bool(REWARD_RE.search(m)))
    # A "bank" message whose link is NOT on the official .bank.in domain.
    s.bank_link_not_bankin = int(bool(s.bank_context and s.has_url and not BANK_IN_RE.search(m)))
    s.sender_is_10_digit = int(bool(sender and TEN_DIGIT_RE.match(normalize_sender(sender))))

    r = s.reasons
    if s.has_apk:
        r.append("asks you to install an app file (.apk) from a link instead of the Play Store")
    if s.asks_secret:
        r.append("talks about your OTP, PIN, CVV or password")
    if s.bank_link_not_bankin:
        r.append("claims to be from a bank, but the link is not on an official .bank.in website")
    if s.sender_is_10_digit and s.bank_context:
        r.append("sent from a 10-digit mobile number, but real banks send SMS from registered sender IDs")
    elif s.sender_is_10_digit and (s.has_url or s.mentions_money or s.urgency or s.asks_secret):
        r.append("sent from a personal 10-digit mobile number, not a registered business sender ID")
    if CALL_NUMBER_RE.search(m):
        r.append("asks you to call or WhatsApp a mobile number")
    if s.has_shortener:
        r.append("uses a short link that hides the real website")
    if s.has_upi:
        r.append("contains a UPI ID for sending money")
    if s.reward_bait:
        r.append("promises a prize, refund or cashback")
    if s.urgency:
        r.append("rushes you with a deadline or a threat to block or cut off a service")
    if s.has_url and not (s.has_apk or s.bank_link_not_bankin or s.has_shortener):
        r.append("contains a link")
    return s


if __name__ == "__main__":
    demo = "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify"
    sig = extract_signals(demo, sender="9812345678")
    print("vector :", sig.vector())
    print("reasons:", sig.reasons)

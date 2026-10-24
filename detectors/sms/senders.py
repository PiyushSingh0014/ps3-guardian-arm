"""Who sent the SMS, and how much that changes the risk.

India's TRAI rules (DLT, since 2021) make businesses send SMS from registered sender IDs
("headers") such as JD-HDFCBK-S: two letters for the operator and region, six characters
for the business, and a suffix for the kind of message: -S service, -T transactional,
-G government, -P promotional. Business SMS from personal 10-digit mobile numbers are not
allowed, which is why scam SMS so often come from them.

The text model never sees the sender (the public training data has none), so the sender is
applied afterwards, as evidence that multiplies the odds of fraud. The multipliers below are
prior assumptions taken from these rules, not values fitted to a test set.
"""
import re
from dataclasses import dataclass
from typing import Optional

from rules_india import TEN_DIGIT_RE, normalize_sender

# XY-ABCDEF-S, XY-ABCDEF, or ABCDEF (some phones drop the prefix). Six letters/digits.
HEADER_RE = re.compile(r"^(?:([A-Z]{2})-)?([A-Z0-9]{6})(?:-([PSTG]))?$")

# Odds multipliers for fraud.
HEADER_ODDS = {"S": 0.02, "T": 0.02, "G": 0.02,   # service, transactional, government
               "P": 0.1,                          # promotional: marketing, rarely fraud
               "": 0.1}                           # registered header without a suffix
MOBILE_RISKY_ODDS = 4.0     # a personal number sending links, money, urgency, bank words or OTP talk

KIND_NAMES = {"business": "registered_sender_id", "mobile": "mobile_number",
              "other": "other", "unknown": "unknown"}


@dataclass(frozen=True)
class SenderInfo:
    kind: str                # "business", "mobile", "other" or "unknown"
    suffix: str = ""         # P, S, T or G for a business header with a suffix
    header: str = ""         # the header as given, upper case

    @property
    def type_name(self):
        return KIND_NAMES[self.kind]


def classify_sender(sender: Optional[str]) -> SenderInfo:
    """'JD-HDFCBK-S' -> business/S; '+91 98123 45678' -> mobile; '' -> unknown; names -> other."""
    raw = (sender or "").strip()
    if not raw:
        return SenderInfo("unknown")
    if TEN_DIGIT_RE.match(normalize_sender(raw)):
        return SenderInfo("mobile")
    up = re.sub(r"\s+", "", raw).upper()
    m = HEADER_RE.match(up)
    # a bare six-digit sender is more likely a short code than a header
    if m and (m.group(1) or not m.group(2).isdigit()):
        return SenderInfo("business", m.group(3) or "", up)
    return SenderInfo("other")


def sender_odds(info: SenderInfo, sig) -> float:
    """How much more (>1) or less (<1) likely fraud is, given who sent the message."""
    if info.kind == "business":
        return HEADER_ODDS[info.suffix]
    risky = sig.has_url or sig.mentions_money or sig.urgency or sig.asks_secret or sig.bank_context \
        or sig.reward_bait
    if info.kind == "mobile" and risky:
        return MOBILE_RISKY_ODDS
    return 1.0


def apply_sender(score: float, info: SenderInfo, sig) -> float:
    """Multiply the odds of the text score by the sender's odds multiplier."""
    k = sender_odds(info, sig)
    if k == 1.0:
        return score
    p = min(max(score, 1e-6), 1 - 1e-6)
    odds = p / (1 - p) * k
    return odds / (1 + odds)

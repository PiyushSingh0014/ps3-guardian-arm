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
import json
import os
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
NO_SUFFIX_ODDS = 0.3        # rule "suffix": since May 2025 every business header carries -P/-S/-T/-G, so a
                            # header without one gets about the geometric middle of a promotional ID (0.1)
                            # and an unknown sender (1)

# Sender rules from the hard review, each switched on only after it has been measured on real
# messages (detectors/sms/eval_senders.py --apply writes the file):
#   suffix  a header without a suffix is trusted less (NO_SUFFIX_ODDS)
#   cap     the sender cannot clear a message that asks for an OTP, PIN or password, or that names a
#           bank, regulator, payment app or government office and has a link that is not safe
#   brand   a risky message that names a brand gets no discount from a sender ID that is not the brand's
SENDER_RULES = ("suffix", "cap", "brand")
_HERE = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "data", "sms", "sender_rules.json")
_cache = {}


def active_rules(path=None):
    """The rules switched on in data/sms/sender_rules.json (GUARDIAN_SENDER_RULES overrides the path);
    none while the file is missing, as before update 37. Re-read when the file changes."""
    path = path or os.environ.get("GUARDIAN_SENDER_RULES", RULES_FILE)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return frozenset()
    if _cache.get(path, (None,))[0] != mtime:
        try:
            with open(path, encoding="utf-8") as f:
                names = json.load(f).get("rules", [])
            rules = frozenset(r for r in names if r in SENDER_RULES)
        except (OSError, ValueError, AttributeError):
            rules = frozenset()
        _cache[path] = (mtime, rules)
    return _cache[path][1]

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

    @property
    def root(self):
        """The six characters of a business header (SBIBNK in JD-SBIBNK-S)."""
        m = HEADER_RE.match(self.header)
        return m.group(2) if m else ""


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


def sender_odds(info: SenderInfo, sig, rules=frozenset()) -> float:
    """How much more (>1) or less (<1) likely fraud is, given who sent the message."""
    if info.kind == "business":
        if not info.suffix and "suffix" in rules:
            return NO_SUFFIX_ODDS
        return HEADER_ODDS[info.suffix]
    risky = sig.has_url or sig.mentions_money or sig.urgency or sig.asks_secret or sig.bank_context \
        or sig.reward_bait
    if info.kind == "mobile" and risky:
        return MOBILE_RISKY_ODDS
    return 1.0


def apply_sender(score: float, info: SenderInfo, sig, rules=frozenset(), k=None) -> float:
    """Multiply the odds of the text score by the sender's odds multiplier (k, if given)."""
    k = sender_odds(info, sig, rules) if k is None else k
    if k == 1.0:
        return score
    p = min(max(score, 1e-6), 1 - 1e-6)
    odds = p / (1 - p) * k
    return odds / (1 + odds)

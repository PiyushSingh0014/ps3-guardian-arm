"""Who a message claims to be from, picked from a fixed list.

The advisor tells Llama who a message pretends to be from. The name always
comes from this list and never from the message itself, so text written by
a scammer cannot reach the model through this field.

Add organisations as you meet them in your India test set. Keep each pattern
specific: a short pattern that also matches ordinary words gives wrong names.
"""
import re

# (name shown to the model, kind, pattern). Matching is case-insensitive.
_BRANDS = [
    ("SBI", "bank", r"\bsbi\b|\bstate bank of india\b"),
    ("HDFC Bank", "bank", r"\bhdfc\b"),
    ("ICICI Bank", "bank", r"\bicici\b"),
    ("Axis Bank", "bank", r"\baxis\s*bank\b"),
    ("Kotak Mahindra Bank", "bank", r"\bkotak\b"),
    ("Punjab National Bank", "bank", r"\bpnb\b|\bpunjab national bank\b"),
    ("Bank of Baroda", "bank", r"\bbank of baroda\b"),
    ("Canara Bank", "bank", r"\bcanara\s*bank\b"),
    ("Union Bank of India", "bank", r"\bunion bank\b"),
    ("Yes Bank", "bank", r"\byes\s*bank\b"),
    ("IndusInd Bank", "bank", r"\bindusind\b"),
    ("IDFC FIRST Bank", "bank", r"\bidfc\b"),
    ("the Reserve Bank of India", "regulator", r"\brbi\b|\breserve bank\b"),
    ("Paytm", "payment app", r"\bpaytm\b"),
    ("PhonePe", "payment app", r"\bphone\s?pe\b"),
    ("Google Pay", "payment app", r"\bgoogle\s?pay\b|\bgpay\b"),
    ("India Post", "courier", r"\bindia\s?post\b|\bspeed\s?post\b"),
    ("Blue Dart", "courier", r"\bblue\s?dart\b"),
    ("Delhivery", "courier", r"\bdelhivery\b"),
    ("DTDC", "courier", r"\bdtdc\b"),
    ("FedEx", "courier", r"\bfedex\b"),
    ("DHL", "courier", r"\bdhl\b"),
    ("Amazon", "online shop", r"\bamazon\b"),
    ("Flipkart", "online shop", r"\bflipkart\b"),
    ("Jio", "mobile operator", r"\bjio\b"),
    ("Airtel", "mobile operator", r"\bairtel\b"),
    ("Vodafone Idea (Vi)", "mobile operator", r"\bvodafone\b"),
    ("BSNL", "mobile operator", r"\bbsnl\b"),
    ("TRAI", "government", r"\btrai\b"),
    ("the Income Tax Department", "government", r"\bincome[\s-]?tax\b"),
    ("the CBI", "government", r"\bcbi\b"),
    ("the police", "government", r"\bpolice\b|\bcyber\s?cell\b"),
    ("customs officials", "government", r"\bcustoms\b"),
    ("UIDAI (Aadhaar)", "government", r"\baadhaa?r\b|\buidai\b"),
    ("EPFO", "government", r"\bepfo\b|\bprovident fund\b"),
    ("the electricity company", "utility", r"\belectricity\b|\bpower supply\b|\blight bill\b|\bbijli\b"),
    ("the gas company", "utility", r"\bindane\b|\bgas (?:connection|booking|subsidy)\b"),
]
BRANDS = [(name, kind, re.compile(rx, re.I)) for name, kind, rx in _BRANDS]

# The roots found in each brand's registered sender IDs (the six characters in JD-SBIBNK-S), as
# far as the team knows them. A brand without roots is never checked against its sender ID.
# TRAI's full header list (Header Information Portal) would replace this guess.
HEADER_ROOTS = {
    "SBI": ("SBI",), "HDFC Bank": ("HDFC",), "ICICI Bank": ("ICICI",), "Axis Bank": ("AXIS",),
    "Kotak Mahindra Bank": ("KOTAK",), "Punjab National Bank": ("PNB",), "Bank of Baroda": ("BOB", "BARODA"),
    "Canara Bank": ("CANBNK", "CANARA"), "Yes Bank": ("YESB",), "IndusInd Bank": ("INDUS",),
    "IDFC FIRST Bank": ("IDFC",), "the Reserve Bank of India": ("RBI",), "Paytm": ("PAYTM", "PYTM"),
    "PhonePe": ("PHONPE", "PHNPE"), "Google Pay": ("GPAY", "GOOGLE"), "India Post": ("INDPST", "INPOST", "IPOST"),
    "Amazon": ("AMAZON", "AMZN"), "Flipkart": ("FLPKRT", "FKRT", "FLIPKT"), "Jio": ("JIO",),
    "Airtel": ("AIRTEL", "ARTL"), "BSNL": ("BSNL",), "TRAI": ("TRAI",), "UIDAI (Aadhaar)": ("UIDAI", "AADHAR"),
    "EPFO": ("EPFO",),
}


def brands_named(text):
    """Every (name, kind) from the list that the message names."""
    return [(name, kind) for name, kind, rx in BRANDS if rx.search(text or "")]


def header_belongs(root, names):
    """True if the six-character root of a sender ID contains a known root of one of the brands."""
    root = (root or "").upper()
    return any(r in root for name in names for r in HEADER_ROOTS.get(name, ()))


# For each scam type, which kinds of organisation the scammer usually pretends to be.
_PREFERRED = {
    "bank_kyc_scam": ("bank", "regulator", "payment app"),
    "otp_theft": ("bank", "payment app", "mobile operator", "online shop"),
    "delivery_fee_scam": ("courier", "online shop", "government"),
    "utility_disconnection_scam": ("utility", "mobile operator"),
    "digital_arrest_scam": ("government",),
    "apk_malware_link": ("bank", "payment app", "government", "utility", "courier"),
}


def claimed_identity(text, category=None):
    """Return (name, kind) of the organisation the message claims to be, or (None, None)."""
    hits = [(name, kind) for name, kind, rx in BRANDS if rx.search(text or "")]
    if not hits:
        return None, None
    for kind in _PREFERRED.get(category, ()):
        for name, k in hits:
            if k == kind:
                return name, k
    return hits[0]

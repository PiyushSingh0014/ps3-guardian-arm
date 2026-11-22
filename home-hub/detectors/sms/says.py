"""What a flagged message itself says, in fixed words (prompt v5, update 47).

Llama is never shown the message: a scammer's words could steer it. With only the scam type and the
warning signs, its explanation was the same for every message of a type ("pretends to be your bank
to steal your login"), even when the message threatened something else. These patterns find the
message's own claim, the amount, the deadline and what it asks you to do, and name each in fixed
words ("says your electricity will be cut off", "mentions ₹25,000", "asks you to pay money"). Llama
is shown those words, so its explanation is about this message, and its answer is still held to
them by the checks: nothing the message says reaches Llama except these phrases and an amount.

The rules are tried in order and at most MAX_SAYS phrases are kept: the claim first, then the amount,
the deadline and what the message asks. An OTP is only "talked about": a bank's own OTP message
says the same words as a scam that asks for it, and the warning signs say which it is.
scripts/export_phone_guard.py copies them to the phone app,
which finds the same phrases (Phone Guard).
"""
import re

MAX_SAYS = 4

# (pattern, phrase). "{0}" in a phrase is the pattern's first group (the amount).
SAYS = [
    # What the message claims: the threat or the bait.
    (r"\b(?:account|a/c|acct)\b[^.!?\n]{0,40}\b(?:block|suspend|freez|deactivat|clos|disabl)\w*"
     r"|\b(?:block|suspend|freez|deactivat|disabl)\w*[^.!?\n]{0,30}\b(?:account|a/c|acct)\b",
     "says your bank account will be blocked"),
    (r"\bcards?\b[^.!?\n]{0,30}\b(?:block|suspend|deactivat)\w*", "says your card will be blocked"),
    (r"\b(?:sim|mobile number)\b[^.!?\n]{0,30}\b(?:block|deactivat|suspend|disconnect)\w*",
     "says your SIM or number will be blocked"),
    (r"\b(?:electri ?city|power|light|bijli)\b[^.!?\n]{0,50}\b(?:dis-?connect|cut|discontinu)\w*"
     r"|\bdis-?connect\w*[^.!?\n]{0,50}\b(?:electri ?city|power)\b",
     "says your electricity will be cut off"),
    (r"\b(?:parcel|package|shipment|courier|consignment)\b", "talks about a parcel or delivery"),
    (r"\b(?:won|winner|lucky draw|lottery|jackpot|prize)\b", "says you have won a prize"),
    (r"\b(?:refund|cashback|cash back)\b", "promises a refund or cashback"),
    (r"\b(?:part[- ]time|work from home|job offer|daily (?:income|earning|salary)|per day)\b",
     "offers a job or easy money"),
    (r"\bloans?\b[^.!?\n]{0,30}\b(?:approved|sanction\w*|pre-approved|eligible)",
     "says a loan is approved for you"),
    (r"\b(?:arrest\w*|cbi|police|narcotics|money laundering|court|fir|customs officer)\b",
     "threatens police or legal action"),
    (r"\b(?:invest\w*|trading|stock tips?|crypto|bitcoin)\b", "talks about an investment"),
    (r"\breward points?\b", "talks about reward points"),
    # The same claims in Hindi.
    (r"खात[ाे][^.!?\n।]{0,40}(?:बंद|ब्लॉक)", "says your bank account will be blocked"),
    (r"बिजली[^.!?\n।]{0,50}(?:कट|काट|बंद)", "says your electricity will be cut off"),
    (r"लॉटरी|इनाम|जीत", "says you have won a prize"),
    (r"पार्सल", "talks about a parcel or delivery"),
    # How much: a whole amount that is not zero ("Rs.0 balance", "Rs. 0.45 premium" are left out).
    (r"(?:₹|\brs\.?|\binr)\s?([1-9]\d{0,2}(?:,\d{2,3})+|[1-9]\d*)", "mentions ₹{0}"),
    # The deadline.
    (r"\b(?:today|tonight|immediately|urgent\w*|within \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)"
     r"|24 ?hours?|last (?:date|day|chance))\b|आज|तुरंत",
     "says you must act now"),
    # What it asks you to do.
    (r"\b(?:otp|one[- ]time password|cvv|upi pin|m-?pin|atm pin|password)\b", "talks about an OTP, PIN or password"),
    (r"\b(?:pay|deposit|transfer)\b[^.!?\n]{0,40}\b(?:fee|charges?|fine|penalty|amount)\b"
     r"|\b(?:fee|charges?|fine|penalty)\b[^.!?\n]{0,30}\b(?:pay|deposit)\w*",
     "asks you to pay money"),
    (r"\b(?:install|download)\b[^.!?\n]{0,30}\b(?:app|apk|application)\b|\.apk\b", "asks you to install an app"),
    (r"\b(?:call|contact|dial|whatsapp)\b[^.!?\n]{0,30}"
     r"(?:\d{10}|\+91|\bnumber\b|\bhelpline\b|\bofficer\b|\bexecutive\b|\bus\b|\bme\b|\bimmediately\b|\bnow\b)",
     "asks you to call or message someone"),
    (r"\b(?:update|verify|complete|link)\b[^.!?\n]{0,25}\b(?:kyc|pan|aadhaar|aadhar|details?|account|address)\b",
     "asks you to update or verify your details"),
    (r"अपडेट|सत्यापित", "asks you to update or verify your details"),
    (r"https?://|\bwww\.|\b(?:click|tap)\b[^.!?\n]{0,20}\b(?:link|here|below)\b", "has a link to open"),
]

_RULES = [(re.compile(p, re.I), phrase) for p, phrase in SAYS]


def message_says(text):
    """The phrases for this (cleaned) message, in rule order, without repeats, at most MAX_SAYS."""
    out = []
    for rx, phrase in _RULES:
        m = rx.search(text or "")
        if not m:
            continue
        said = phrase.replace("{0}", m.group(1)) if "{0}" in phrase else phrase
        if said not in out:
            out.append(said)
        if len(out) == MAX_SAYS:
            break
    return out

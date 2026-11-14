"""Builds the Llama 3.2 Instruct prompt for the advisor (v4).

v4 (after the first Pi benchmark): each case also says what the scammer wants
(the playbook's `wants:` line), and sentence 2 is asked for as "the checked
fact and the first warning sign". On the Pi, v3 guessed the scammer's goal
("to trick you into giving away your income-tax refund") and padded sentence 2
with made-up claims ("links to their websites are always correct").

What changed from v2, and why:
  * Evidence only. Llama sees the scanner result, the scam type and one checked
    fact from the playbook, the warning signs the detector found, and who the
    message claims to be from (picked from a fixed list). The message text
    itself is never sent, so a scammer's words cannot steer the model.
  * Worked examples instead of rules. A 1B model copies examples far better
    than it follows instructions, and it misreads negative rules ("never call
    it safe" made it refuse). So the system text is short and positive, and
    three examples show the exact 2-sentence answer we want.
  * A fixed prefix. Everything up to the current alert (system text plus the
    examples) is identical for every alert, so the persistent Llama service
    reads it once at start-up and reuses its KV cache. Only the ~100 tokens of
    the alert itself are read per request.
  * Llama writes only the explanation. The code picks the remediation steps.

Network alerts (source "net") get a prompt of their own: other system text and other
worked examples, because "who the message pretends to be from" does not fit a device that
scans or calls home. The service reads that prefix when a network alert comes and goes back
to the message prefix when idle. Addresses and names in the monitor's reasons are replaced
before Llama sees them: the alerting device becomes "the device", other addresses "another
device on your network" or "a server on the internet", and website names "a website".
Names are chosen by whoever registered them, so none reaches Llama, and two alerts of the
same kind share one prompt (the answer cache then makes the second one instant).
"""
import ipaddress
import re

from .findings import describe_org

# Set False and run llama_main with --num_bos 1 if your tokenizer build
# does not turn the "<|begin_of_text|>" string into the BOS token.
INCLUDE_BOS_TOKEN = True
MAX_UNTRUSTED_CHARS = 300
MAX_SIGNS = 4
MAX_NEW_TOKENS = {"en": 64, "hi": 160}      # Hindi needs ~3x more tokens for the same text
MAX_NEW_TOKENS_NET = 72                    # network answers name an action and a fact: a little longer
LANG_NAMES = {"en": "simple English", "hi": "simple Hindi, written in Devanagari script"}

_SPECIAL_TOKEN_RE = re.compile(r"<\|[^|>]{0,40}\|>")
_FENCE_RE = re.compile(r"</?\s*untrusted\s*>", re.I)
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.I)

SYSTEM = (
    "You explain scam alerts to people in India in {lang}. "
    "A security scanner has already checked the message and listed what it found. "
    "Using only those facts, write exactly 2 short sentences. "
    "Sentence 1: who the message pretends to be from and what the scammer wants. "
    "Sentence 2: the checked fact and the first warning sign."
)

RESULT_TEXT = {"dangerous": "scam (high confidence)",
               "suspicious": "possible scam (medium confidence)"}

# Worked examples. They are part of the fixed prefix, so they cost prefill time
# only once, when the service starts. Keep them short, varied and correct: the
# model copies their style, length and tone.
EXAMPLES = [
    {
        "result": RESULT_TEXT["dangerous"],
        "scam_type": "Fake electricity or bill disconnection",
        "pretends": "the electricity company",
        "wants": "to scare you into paying a scammer",
        "signs": ["asks you to call or WhatsApp a mobile number",
                  "rushes you with a deadline or a threat to block or cut off a service"],
        "fact": ("Electricity companies send disconnection notices with the official bill and do "
                 "not ask you to call a personal mobile number or install an app."),
        "answer": {
            "en": ("This message pretends to be from your electricity company to scare you into "
                   "paying a scammer. Real electricity companies send notices with the bill and do "
                   "not ask you to call a personal number."),
            "hi": ("यह संदेश आपकी बिजली कंपनी के नाम पर भेजा गया है, ताकि आप डरकर ठग को पैसे दे "
                   "दें। असली बिजली कंपनियाँ नोटिस बिल के साथ भेजती हैं और किसी निजी नंबर पर कॉल "
                   "करने को नहीं कहतीं।"),
        },
    },
    {
        "result": RESULT_TEXT["dangerous"],
        "scam_type": "Fake parcel or delivery fee",
        "pretends": "India Post (a courier company)",
        "wants": "to steal your card details through a fake delivery fee",
        "signs": ["uses a short link that hides the real website",
                  "rushes you with a deadline or a threat to block or cut off a service"],
        "fact": ("Courier companies and India Post do not ask for redelivery, address-update or "
                 "customs fees through links in SMS messages."),
        "answer": {
            "en": ("This message pretends to be from India Post to steal your card details through "
                   "a fake delivery fee. India Post does not collect fees through SMS links, and "
                   "this short link hides the real website."),
            "hi": ("यह संदेश इंडिया पोस्ट के नाम पर नकली डिलीवरी फीस के बहाने आपके कार्ड की "
                   "जानकारी चुराने के लिए भेजा गया है। इंडिया पोस्ट SMS लिंक से फीस नहीं लेता, और "
                   "यह छोटा लिंक असली वेबसाइट छिपाता है।"),
        },
    },
    {
        "result": RESULT_TEXT["suspicious"],
        "scam_type": "OTP or password theft",
        "pretends": "Paytm (a payment app)",
        "wants": "to get your OTP and empty your account",
        "signs": ["talks about your OTP, PIN, CVV or password",
                  "promises a prize, refund or cashback"],
        "fact": ("No bank, company or government office ever asks you to share an OTP; anyone who "
                 "has your OTP can take money from your account or take over your apps."),
        "answer": {
            "en": ("This message looks like someone pretending to be Paytm to get your OTP and empty "
                   "your account. Real companies never ask for your OTP, and promised cashback is "
                   "a common bait."),
            "hi": ("यह संदेश Paytm के नाम पर आपका OTP पाकर खाता खाली करने की कोशिश जैसा लगता है। "
                   "असली कंपनियाँ कभी OTP नहीं माँगतीं, और कैशबैक का वादा अक्सर एक चारा होता है।"),
        },
    },
]


def defang(text):
    def _defang(m):
        url = re.sub(r"^http", "hxxp", m.group(0), flags=re.I)
        return url.replace(".", "[.]")
    return _URL_RE.sub(_defang, text)


def sanitize_untrusted(text, limit=MAX_UNTRUSTED_CHARS):
    """For any text a sender could have written. v3 sends none to Llama by
    default, but keep using this if you ever add message excerpts."""
    t = (text or "")[:limit]
    t = _SPECIAL_TOKEN_RE.sub(" ", t)   # no chat-template tokens smuggled in
    t = _FENCE_RE.sub(" ", t)           # cannot close a fence early
    t = defang(t)                       # links become inert text
    return " ".join(t.split())


def _field(text, limit=220):
    """Clean a trusted field: one line, no chat-template tokens, bounded length.
    (Defence in depth: a future detector could put odd text in its reasons.)"""
    t = _SPECIAL_TOKEN_RE.sub(" ", str(text or ""))
    return " ".join(t.split())[:limit]


def _header(role):
    return f"<|start_header_id|>{role}<|end_header_id|>\n\n"


def format_case(result, scam_type, pretends, signs, fact, wants=""):
    # Fixed-per-scam-type lines come first: two alerts of the same type then share
    # these tokens too, and the service does not read them again.
    lines = [f"Scam type: {_field(scam_type)}"]
    if wants:
        lines.append(f"Scammer wants: {_field(wants)}")
    if fact:
        lines.append(f"Fact: {_field(fact, 300)}")
    lines += [f"Scanner result: {_field(result)}",
              f"Pretends to be: {_field(pretends)}",
              "Warning signs:"]
    lines += [f"- {_field(s)}" for s in signs[:MAX_SIGNS]] or ["- text patterns common in scam messages"]
    return "\n".join(lines)


def pretends_to_be(finding, playbook):
    # Only the detector's trusted entity (from a fixed list) or the playbook text.
    name = finding.entities.get("claims_to_be")
    if name:
        return describe_org(name, finding.entities.get("claims_kind"))
    return playbook.pretends or "someone you might trust"


def build_user_turn(finding, playbook):
    return format_case(result=RESULT_TEXT.get(finding.verdict, RESULT_TEXT["suspicious"]),
                       scam_type=playbook.title,
                       pretends=pretends_to_be(finding, playbook),
                       signs=finding.reasons,
                       fact=playbook.fact,
                       wants=playbook.wants)


def case_text(finding, playbook):
    """The case Llama is shown for this alert (its user turn): all the evidence it has, so the
    validator's grounding checks hold its answer to it."""
    return build_net_user_turn(finding, playbook) if finding.source == "net" else build_user_turn(finding, playbook)


def static_prefix(language="en", n_examples=len(EXAMPLES)):
    """System text plus worked examples: identical for every alert in a language."""
    lang = language if language in LANG_NAMES else "en"
    bos = "<|begin_of_text|>" if INCLUDE_BOS_TOKEN else ""
    parts = [bos, _header("system"), SYSTEM.format(lang=LANG_NAMES[lang]), "<|eot_id|>"]
    for ex in EXAMPLES[:n_examples]:
        case = format_case(ex["result"], ex["scam_type"], ex["pretends"], ex["signs"], ex["fact"], ex["wants"])
        parts += [_header("user"), case, "<|eot_id|>", _header("assistant"), ex["answer"][lang], "<|eot_id|>"]
    return "".join(parts)


def build_prompt(finding, playbook, n_examples=None):
    """n_examples: how many worked examples to include (default: all of that prompt's)."""
    if finding.source == "net":
        n = len(EXAMPLES_NET) if n_examples is None else min(n_examples, len(EXAMPLES_NET))
        return (static_prefix_net(n)
                + _header("user") + build_net_user_turn(finding, playbook) + "<|eot_id|>"
                + _header("assistant"))
    n = len(EXAMPLES) if n_examples is None else n_examples
    return (static_prefix(finding.language, n)
            + _header("user") + build_user_turn(finding, playbook) + "<|eot_id|>"
            + _header("assistant"))


def max_new_tokens(language, source="sms"):
    if source == "net":
        return MAX_NEW_TOKENS_NET
    return MAX_NEW_TOKENS.get(language, MAX_NEW_TOKENS["en"])


# --- network alerts ------------------------------------------------------------------
SYSTEM_NET = (
    "You explain network alerts to people in India in {lang}. "
    "A monitor on their Wi-Fi has already checked a device's connections and listed what it saw. "
    "Using only those facts, write exactly 2 short sentences. "
    "Sentence 1: what the device did and what the attacker or malware wants. "
    "Sentence 2: the checked fact and why it is a warning sign."
)

RESULT_TEXT_NET = {"dangerous": "attack or malware (high confidence)",
                   "suspicious": "possible attack or malware (medium confidence)"}

EXAMPLES_NET = [
    {
        "result": RESULT_TEXT_NET["dangerous"],
        "alert_type": "Port scan on your network",
        "wants": "to find an open door into your devices",
        "fact": ("Normal phones, laptops and sensors connect to a few ports on a few servers; trying dozens "
                 "of ports on one device in a minute is what scanning tools do."),
        "saw": ["the device tried 100 different ports on another device on your network within 5 seconds, "
                "most of them closed: that is how attackers look for a way in"],
        "answer": ("A device on your Wi-Fi tried 100 different ports on another device in a few seconds, "
                   "looking for an open door into your devices. Normal phones and sensors use only a few "
                   "ports, so this is what scanning tools do."),
    },
    {
        "result": RESULT_TEXT_NET["suspicious"],
        "alert_type": "Device calling home at fixed times (possible malware)",
        "wants": "to keep control of your device and wait for orders",
        "fact": ("Malware contacts its controller at fixed intervals; normal apps do too, so a rhythm to an "
                 "unknown server is a warning sign, not proof."),
        "saw": ["the device contacts a server on the internet every 2 minutes, like clockwork (12 times so "
                "far): malware checks in with its controller this way"],
        "answer": ("A device on your Wi-Fi contacts the same unknown server every 2 minutes, which is how "
                   "malware keeps control of a device and waits for orders. Some normal apps also call home "
                   "on a timer, so this is a warning sign to check, not proof."),
    },
    {
        "result": RESULT_TEXT_NET["dangerous"],
        "alert_type": "Device opened a phishing website",
        "wants": "to steal a password, card details or OTP through a fake website",
        "fact": ("Real Indian bank websites end in .bank.in and government websites end in .gov.in; a site on "
                 "the phishing lists has been reported for stealing details."),
        "saw": ["the device looked up a fake website: the website address uses HDFC Bank's name, but it is "
                "not HDFC Bank's official website"],
        "answer": ("A device on your Wi-Fi opened a fake website that uses HDFC Bank's name to steal a "
                   "password, card details or OTP. Real Indian bank websites end in .bank.in, and this "
                   "address is not HDFC Bank's official website."),
    },
    {   # added after the Pi: without it, Llama wrote "flagged as a scam by the device itself"
        "result": RESULT_TEXT_NET["dangerous"],
        "alert_type": "Link from a scam message opened",
        "wants": "to steal a password, card details or OTP through the link in the message",
        "fact": ("A message carrying this website's link was flagged as a scam before the link was opened; fake pages "
                 "copy real ones, so anything typed there goes to the scammer."),
        "saw": ["the device opened a website from a scam message: the message was flagged at 21:02 (an SMS from a "
                "mobile number)"],
        "answer": ("A device on your Wi-Fi opened the link from a scam SMS that came from a mobile number at 21:02, a "
                   "fake page made to steal a password, card details or OTP. The message was flagged as a scam before "
                   "the link was opened, and anything typed on such a page goes to the scammer."),
    },
]

_IP_RE = re.compile(r"(?<![\w.:])(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w.:])", re.I)


def net_reason(text, device=""):
    """A monitor reason with its addresses and names replaced by plain words."""
    def address(m):
        a = m.group(0)
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return a                           # not an address after all, e.g. a time "13:29:05"
        if a == device:
            return "the device"
        return "another device on your network" if ip.is_private else "a server on the internet"
    t = _IP_RE.sub(address, str(text or ""))
    t = _URL_RE.sub("a website", t)
    return _field(t, 260)


def format_net_case(result, alert_type, wants, fact, saw):
    # As for messages, the lines fixed per alert type come first.
    lines = [f"Alert type: {_field(alert_type)}"]
    if wants:
        lines.append(f"Attacker or malware wants: {_field(wants)}")
    if fact:
        lines.append(f"Fact: {_field(fact, 300)}")
    lines += [f"Monitor result: {_field(result)}", "What the monitor saw:"]
    lines += [f"- {_field(s, 260)}" for s in saw[:MAX_SIGNS]] or ["- unusual connections"]
    return "\n".join(lines)


def build_net_user_turn(finding, playbook):
    device = str(finding.entities.get("device", ""))
    return format_net_case(result=RESULT_TEXT_NET.get(finding.verdict, RESULT_TEXT_NET["suspicious"]),
                           alert_type=playbook.title, wants=playbook.wants, fact=playbook.fact,
                           saw=[net_reason(r, device) for r in finding.reasons])


def static_prefix_net(n_examples=len(EXAMPLES_NET)):
    """System text plus worked examples for network alerts (English): identical for every alert."""
    bos = "<|begin_of_text|>" if INCLUDE_BOS_TOKEN else ""
    parts = [bos, _header("system"), SYSTEM_NET.format(lang=LANG_NAMES["en"]), "<|eot_id|>"]
    for ex in EXAMPLES_NET[:n_examples]:
        case = format_net_case(ex["result"], ex["alert_type"], ex["wants"], ex["fact"], ex["saw"])
        parts += [_header("user"), case, "<|eot_id|>", _header("assistant"), ex["answer"], "<|eot_id|>"]
    return "".join(parts)

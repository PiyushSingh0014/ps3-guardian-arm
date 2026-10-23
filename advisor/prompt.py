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
"""
import re

from .findings import describe_org

# Set False and run llama_main with --num_bos 1 if your tokenizer build
# does not turn the "<|begin_of_text|>" string into the BOS token.
INCLUDE_BOS_TOKEN = True
MAX_UNTRUSTED_CHARS = 300
MAX_SIGNS = 4
MAX_NEW_TOKENS = {"en": 64, "hi": 160}      # Hindi needs ~3x more tokens for the same text
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


def static_prefix(language="en", n_examples=len(EXAMPLES)):
    """System text plus worked examples: identical for every alert in a language."""
    lang = language if language in LANG_NAMES else "en"
    bos = "<|begin_of_text|>" if INCLUDE_BOS_TOKEN else ""
    parts = [bos, _header("system"), SYSTEM.format(lang=LANG_NAMES[lang]), "<|eot_id|>"]
    for ex in EXAMPLES[:n_examples]:
        case = format_case(ex["result"], ex["scam_type"], ex["pretends"], ex["signs"], ex["fact"], ex["wants"])
        parts += [_header("user"), case, "<|eot_id|>", _header("assistant"), ex["answer"][lang], "<|eot_id|>"]
    return "".join(parts)


def build_prompt(finding, playbook, n_examples=len(EXAMPLES)):
    return (static_prefix(finding.language, n_examples)
            + _header("user") + build_user_turn(finding, playbook) + "<|eot_id|>"
            + _header("assistant"))


def max_new_tokens(language):
    return MAX_NEW_TOKENS.get(language, MAX_NEW_TOKENS["en"])

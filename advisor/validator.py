"""Checks every Llama explanation before a user sees it (v3: 2-sentence answers).

The detectors own the verdict; Llama only explains. So this module:
  * rejects answers that contradict the verdict ("this is safe") or that are
    not in the requested language,
  * drops any sentence that contains a phone number or link not on the
    allowlist, so a number or URL can never reach the user through Llama,
  * keeps at most 2 complete sentences (a sentence cut off by the token limit
    is dropped) and about 60 words (80 in Hindi),
  * applies two small deterministic fixes seen on the Pi: hedging ("is likely
    a scam") when the scanner is confident, and wrong KYC expansions,
  * grounding (update 38, from the hard review): given the case Llama was shown (the evidence),
    drops a sentence that states a number, names an organisation, or says "never" or "always"
    when the evidence does not. A small model invents such details; the checks above only
    caught forbidden forms, not invented facts.
  * update 38b, after reading Llama's first 100 graded answers: "never" is grounded by "no ...
    ever" too (the OTP fact says "No bank ... ever asks"); a sentence may not say where the
    message's link goes or that .bank.in/.gov.in sites are not real; and a rule about what real
    companies, banks or people do ("Real companies never ask for links") must come from a case
    whose fact states such a rule.
A rejected answer makes the advisor fall back to its template text; a dropped sentence 2 is
replaced by the template's list of red flags (advisor/advise.py).
"""
import re
from dataclasses import dataclass, field

from detectors.sms.brands import BRANDS

# Text the explanation may mention. "bank.in" and "gov.in" cover phrases such as
# "genuine bank links end in .bank.in"; they are domain endings, not sites.
ALLOWED_DOMAINS = {"cybercrime.gov.in", "sancharsaathi.gov.in", "bank.in", "gov.in"}
ALLOWED_NUMBERS = {"1930"}
MAX_SENTENCES = 2
MAX_WORDS = {"en": 60, "hi": 80}       # Hindi writes postpositions as separate words

# "...updating your KYC, which is a legitimate process" (seen on the Pi) also counts: in a
# scam warning it reads as approval of what the scammer asks for. The second line is for
# network alerts ("this is normal", "not malware").
_CONTRADICTION_RE = re.compile(
    r"\b(?:is|seems|looks|appears)\s+(?:to\s+be\s+)?(?:an?\s+)?(?:safe|legit|legitimate|genuine|harmless|trustworthy)\b"
    r"|\bnot\s+a\s+scam\b|\bno\s+need\s+to\s+worry\b|\bnothing\s+to\s+worry\b|\byou\s+can\s+trust\b"
    r"|\bnot\s+(?:an?\s+)?(?:attack|malware|virus|threat|hacker)\b|\b(?:this|it|that)\s+is\s+(?:completely\s+|perfectly\s+)?normal\b"
    r"|सुरक्षित है|असली है|घोटाला नहीं|धोखाधड़ी नहीं",
    re.I)
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.I)
_PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?\b\d[\d\s-]{4,}\d\b")
_SPECIAL_RE = re.compile(r"<\|[^|>]{0,40}\|>")
_SPLIT_RE = re.compile(r"(?<=[.!?।])\s+")      # end mark + space: "cybercrime.gov.in" stays whole
_ABBREV_RE = re.compile(r"\b(?:rs|e\.g|i\.e|no|mr|mrs|dr|st)\.$", re.I)
_PREAMBLE_RE = re.compile(r"^\s*(?:here (?:is|are)[^:]{0,40}|explanation|answer)\s*:\s*", re.I)
_DEVANAGARI_RE = re.compile(r"[ऀ-ॿ]")
_HEDGES = [
    (re.compile(r"\b(is|are)\s+(?:most\s+)?(?:likely|probably|possibly)\s+", re.I), r"\1 "),
    (re.compile(r"\b(?:most\s+)?(?:likely|probably)\s+(?=(?:a|an)\s+(?:scam|fraud|fake)\b)", re.I), ""),
]
_GLOSSARY = [  # Title-case only, so ordinary phrases such as "you know your bank" are untouched
    (re.compile(r"\bKnow Your (?!Customer\b)[A-Z][a-z]+\b"), "Know Your Customer"),
]


# Organisations Llama might name besides the brand list's (detectors/sms/brands.py).
_EXTRA_ORGS = [("NPCI", r"\bnpci\b"), ("CERT-In", r"\bcert-?in\b"), ("SEBI", r"\bsebi\b"), ("IRCTC", r"\birctc\b"),
               ("LIC", r"\blic\b"), ("WhatsApp", r"\bwhats\s?app\b"), ("Telegram", r"\btelegram\b"),
               ("Google", r"\bgoogle\b"), ("Facebook", r"\bfacebook\b"), ("Instagram", r"\binstagram\b"),
               ("Microsoft", r"\bmicrosoft\b"), ("Apple", r"\bapple\b"), ("Netflix", r"\bnetflix\b"),
               ("Swiggy", r"\bswiggy\b"), ("Zomato", r"\bzomato\b"), ("the ED", r"\benforcement directorate\b"),
               ("the NCB", r"\bncb\b"), ("Interpol", r"\binterpol\b"), ("the FBI", r"\bfbi\b"),
               ("a court", r"\b(?:supreme|high) court\b")]
ORGANISATIONS = [(name, rx) for name, _, rx in BRANDS] + [(n, re.compile(rx, re.I)) for n, rx in _EXTRA_ORGS]
_NUMBER_RE = re.compile(r"\d+")
_ABSOLUTE_RE = re.compile(r"\b(never|always)\b", re.I)
_NO_EVER_RE = re.compile(r"\b(?:no|not|nobody|none|nothing)\b[^.;]*?\bever\b", re.I)   # "No bank ... ever asks"
_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

# The case never says where a message's link goes, and its fact says genuine bank and government
# websites end in .bank.in and .gov.in. Seen on the Pi: "the link ends in .bank.in, not .com",
# "links ending in .bank.in are not real bank websites".
_DOMAIN_CLAIM_RE = re.compile(
    r"\b(?:the|this|its|their)\s+(?:link|website|site|address|url)\s+(?:also\s+)?(?:ends?|is)\s+(?:in|on|with)\s+"
    r"(?:an?\s+)?(?:official\s+)?\.?(?:bank|gov)\.in\b"
    r"|\.(?:bank|gov)\.in(?:\s+(?:websites?|sites?|links?|domains?|addresses?))?,?\s+(?:which\s+)?(?:are|is)\s+not\b",
    re.I)
# A rule about what real companies, banks or people do. Seen on the Pi for suspicious messages,
# whose fact states no rule: Llama copied the worked example's "Real companies never ask for your
# OTP" into "Real companies never ask for personal details or links", which is false.
_RULE_RE = re.compile(
    r"(?:^|[,;]\s*(?:and\s+|but\s+|so\s+)?)(?:real|genuine|legitimate|trusted|official)\b[^.,;]*?"
    r"\b(?:never|do\s+not|don't|does\s+not|doesn't|would\s+not|wouldn't|will\s+not|won't|(?:are|is)\s+unlikely\s+to)\b",
    re.I)
_FACT_RULE_RE = re.compile(r"\b(?:never|not|only|always|no)\b", re.I)


def _says_absolute(word, evidence):
    if re.search(rf"\b{word}\b", evidence, re.I):
        return True
    return word == "never" and bool(_NO_EVER_RE.search(evidence))


def _fact(evidence):
    return next((line[len("Fact:"):] for line in evidence.splitlines() if line.startswith("Fact:")), "")


def ungrounded(sentence, evidence, language="en"):
    """Why a sentence says more than the evidence Llama was given, or None. Numbers (1930, the
    national helpline, is always allowed), organisations, and in English "never" and "always"
    (or "no ... ever"), the link's domain, and rules about what real companies or people do."""
    sent, ev = sentence.translate(_DIGITS), (evidence or "").translate(_DIGITS)
    known = set(_NUMBER_RE.findall(ev)) | ALLOWED_NUMBERS
    extra = [n for n in _NUMBER_RE.findall(sent) if n not in known]
    if extra:
        return f"a number the evidence does not have ({extra[0]})"
    for name, rx in ORGANISATIONS:
        if rx.search(sent) and not rx.search(ev):
            return f"names {name}, which the evidence does not"
    if _DOMAIN_CLAIM_RE.search(sent):
        return "says where the link goes, or that .bank.in or .gov.in sites are not real"
    if language == "en":
        for word in dict.fromkeys(w.lower() for w in _ABSOLUTE_RE.findall(sent)):   # in order: the same reason each run
            if not _says_absolute(word, ev):
                return f'says "{word}", which the evidence does not'
        if _RULE_RE.search(sent) and not _FACT_RULE_RE.search(_fact(ev)):
            return "a rule about what real companies or people do, which the fact does not state"
    return None


@dataclass
class Checked:
    what: str = ""          # sentence 1: who it pretends to be and what the scammer wants
    why: str = ""           # sentence 2: the warning signs
    flags: list = field(default_factory=list)
    ok: bool = False
    # Every complete sentence Llama wrote: (sentence, shown to the user, why not). For grading.
    sentences: list = field(default_factory=list)


def scrub(text, flags):
    """Remove links and phone numbers that are not explicitly allowed."""
    def fix_url(m):
        raw = m.group(0)
        host = re.sub(r"^(?:https?://)?(?:www\.)?", "", raw.lower()).split("/")[0].rstrip(".,;:)")
        if host in ALLOWED_DOMAINS:
            return raw
        flags.append(f"removed link: {raw}")
        return "[link removed]"

    def fix_phone(m):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if digits in ALLOWED_NUMBERS or len(digits) < 6:   # 'Rs 500', '10-digit' are fine
            return raw
        flags.append(f"removed number: {raw.strip()}")
        return "[number removed]"

    return _PHONE_RE.sub(fix_phone, _URL_RE.sub(fix_url, text))


def split_sentences(text):
    out = []
    for part in _SPLIT_RE.split((text or "").strip()):
        if out and _ABBREV_RE.search(out[-1]):         # "Rs. 500" is not a sentence end
            out[-1] += " " + part
        elif part.strip():
            out.append(part.strip())
    return out


def _dehedge(sentence):
    for rx, repl in _HEDGES:
        sentence = rx.sub(repl, sentence)
    return sentence


def _glossary(sentence):
    for rx, repl in _GLOSSARY:
        sentence = rx.sub(repl, sentence)
    return sentence


def check_explanation(raw, verdict, language="en", evidence=None):
    """evidence: the case Llama was shown (prompt.case_text); None skips the grounding checks."""
    c = Checked()
    text = _SPECIAL_RE.split(raw or "", 1)[0]         # stop at the first chat-template token
    text = _PREAMBLE_RE.sub("", " ".join(text.split()))
    if not text:
        c.flags.append("empty LLM output")
        return c
    if verdict in ("suspicious", "dangerous") and _CONTRADICTION_RE.search(text):
        c.flags.append("LLM output contradicts the verdict; template used instead")
        return c
    if language == "hi" and not _DEVANAGARI_RE.search(text):
        c.flags.append("LLM answer is not in Hindi; template used instead")
        return c

    sentences = split_sentences(text)
    complete = [s for s in sentences if s[-1] in ".!?।"]
    if len(complete) < len(sentences):
        c.flags.append("dropped an unfinished sentence (token limit)")
    if len(complete) > MAX_SENTENCES:
        c.flags.append(f"kept the first {MAX_SENTENCES} of {len(complete)} sentences")

    kept = []
    c.sentences = [[s, False, "more than 2 sentences"] for s in complete]
    for i, raw_s in enumerate(complete[:MAX_SENTENCES]):
        before = len(c.flags)
        s = scrub(raw_s, c.flags)
        if len(c.flags) > before:
            # "Call [number removed]" still reads like an instruction: drop the sentence.
            c.flags.append("dropped a sentence that contained a number or link")
            kept.append("")
            c.sentences[i][2] = "a phone number or link"
            continue
        why_not = ungrounded(s, evidence, language) if evidence is not None else None
        if why_not:
            c.flags.append(f"dropped a sentence: {why_not}")
            kept.append("")
            c.sentences[i][2] = why_not
            continue
        fixed = _glossary(_dehedge(s) if verdict == "dangerous" else s)
        if fixed != s:
            c.flags.append("fixed wording (hedge or KYC expansion)")
        kept.append(fixed[:1].upper() + fixed[1:])
        c.sentences[i][1:] = [True, ""]

    limit = MAX_WORDS.get(language, MAX_WORDS["en"])
    while kept and sum(len(s.split()) for s in kept) > limit:
        if kept[-1]:
            c.sentences[len(kept) - 1][1:] = [False, f"answer longer than {limit} words"]
        kept.pop()                                     # drop sentence 2 first
        c.flags.append(f"answer longer than {limit} words; shortened")
    c.what = kept[0] if kept else ""
    c.why = kept[1] if len(kept) > 1 else ""
    c.ok = bool(c.what or c.why)
    if not c.ok and "empty LLM output" not in c.flags:
        c.flags.append("no usable sentence in the LLM answer")
    return c

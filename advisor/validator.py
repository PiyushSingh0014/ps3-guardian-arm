"""Checks every Llama explanation before a user sees it (v3: 2-sentence answers).

The detectors own the verdict; Llama only explains. So this module:
  * rejects answers that contradict the verdict ("this is safe") or that are
    not in the requested language,
  * drops any sentence that contains a phone number or link not on the
    allowlist, so a number or URL can never reach the user through Llama,
  * keeps at most 2 complete sentences (a sentence cut off by the token limit
    is dropped) and about 60 words (80 in Hindi),
  * applies two small deterministic fixes seen on the Pi: hedging ("is likely
    a scam") when the scanner is confident, and wrong KYC expansions.
A rejected answer makes the advisor fall back to its template text.
"""
import re
from dataclasses import dataclass, field

# Text the explanation may mention. "bank.in" covers phrases such as
# "genuine bank links end in .bank.in"; it is a domain suffix, not a site.
ALLOWED_DOMAINS = {"cybercrime.gov.in", "sancharsaathi.gov.in", "bank.in"}
ALLOWED_NUMBERS = {"1930"}
MAX_SENTENCES = 2
MAX_WORDS = {"en": 60, "hi": 80}       # Hindi writes postpositions as separate words

_CONTRADICTION_RE = re.compile(
    r"\b(?:is|seems|looks|appears)\s+(?:to\s+be\s+)?(?:safe|legit|legitimate|genuine|harmless|trustworthy)\b"
    r"|\bnot\s+a\s+scam\b|\bno\s+need\s+to\s+worry\b|\bnothing\s+to\s+worry\b|\byou\s+can\s+trust\b"
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


@dataclass
class Checked:
    what: str = ""          # sentence 1: who it pretends to be and what the scammer wants
    why: str = ""           # sentence 2: the warning signs
    flags: list = field(default_factory=list)
    ok: bool = False


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


def check_explanation(raw, verdict, language="en"):
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
    for s in complete[:MAX_SENTENCES]:
        before = len(c.flags)
        s = scrub(s, c.flags)
        if len(c.flags) > before:
            # "Call [number removed]" still reads like an instruction: drop the sentence.
            c.flags.append("dropped a sentence that contained a number or link")
            kept.append("")
            continue
        fixed = _glossary(_dehedge(s) if verdict == "dangerous" else s)
        if fixed != s:
            c.flags.append("fixed wording (hedge or KYC expansion)")
        kept.append(fixed[:1].upper() + fixed[1:])

    limit = MAX_WORDS.get(language, MAX_WORDS["en"])
    while kept and sum(len(s.split()) for s in kept) > limit:
        kept.pop()                                     # drop sentence 2 first
        c.flags.append(f"answer longer than {limit} words; shortened")
    c.what = kept[0] if kept else ""
    c.why = kept[1] if len(kept) > 1 else ""
    c.ok = bool(c.what or c.why)
    if not c.ok and "empty LLM output" not in c.flags:
        c.flags.append("no usable sentence in the LLM answer")
    return c

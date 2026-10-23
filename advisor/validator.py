"""Checks every LLM answer before a user sees it.

The detectors own the verdict; the LLM only explains. So this module:
  * rejects answers that contradict the verdict ("this is safe"),
  * strips any phone number or link not on the allowlist, so a scammer's
    number or URL can never be repeated back to the user,
  * parses the step numbers the model picked, and caps the length.
Any rejected answer makes the advisor fall back to its template.
"""
import re
from dataclasses import dataclass, field

ALLOWED_DOMAINS = {"cybercrime.gov.in", "sancharsaathi.gov.in"}
ALLOWED_NUMBERS = {"1930"}
MAX_WORDS = 60
MAX_STEPS = 3

_CONTRADICTION_RE = re.compile(
    r"\b(?:is|seems|looks|appears)\s+(?:to\s+be\s+)?(?:safe|legit|legitimate|genuine|harmless|trustworthy)\b"
    r"|\bnot\s+a\s+scam\b|\bno\s+need\s+to\s+worry\b|\bnothing\s+to\s+worry\b|\byou\s+can\s+trust\b"
    r"|सुरक्षित है|असली है|घोटाला नहीं|धोखाधड़ी नहीं",
    re.I)
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.I)
_PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?\b\d[\d\s-]{4,}\d\b")
_FIELD_RE = {
    "what": re.compile(r"what\s+happened\s*:\s*(.+)", re.I),
    "why": re.compile(r"\bwhy\s*:\s*(.+)", re.I),
    "steps": re.compile(r"\bsteps\s*:\s*(.+)", re.I),
}


@dataclass
class Checked:
    what: str = ""
    why: str = ""
    steps: list = field(default_factory=list)   # 1-based indices into the playbook
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
        if digits in ALLOWED_NUMBERS or len(digits) < 6:   # 'Rs 500', '2 hours' are fine
            return raw
        flags.append(f"removed number: {raw.strip()}")
        return "[number removed]"

    return _PHONE_RE.sub(fix_phone, _URL_RE.sub(fix_url, text))


def _cap(text, n=MAX_WORDS):
    words = text.split()
    return " ".join(words[:n]) + (" ..." if len(words) > n else "")


def check_llm_output(raw, verdict, n_steps):
    c = Checked()
    text = (raw or "").strip()
    if not text:
        c.flags.append("empty LLM output")
        return c

    if verdict in ("suspicious", "dangerous") and _CONTRADICTION_RE.search(text):
        c.flags.append("LLM output contradicts the verdict; template used instead")
        return c

    fields = {}
    for key, rx in _FIELD_RE.items():
        m = rx.search(text)
        fields[key] = m.group(1).strip() if m else ""

    if not fields["what"] and not fields["why"]:
        c.flags.append("format not followed; first line used as the explanation")
        fields["what"] = text.splitlines()[0]

    # A field the model tried to put a number or link into is dropped entirely
    # (the advisor then uses the playbook text for it). "Call [number removed]"
    # still reads like an instruction, so it must never reach the user.
    for key in ("what", "why"):
        before = len(c.flags)
        cleaned = scrub(fields[key], c.flags)
        if len(c.flags) > before:
            c.flags.append(f"dropped LLM '{key}' text after removing a number or link")
            cleaned = ""
        setattr(c, key, _cap(cleaned))

    chosen = []
    for tok in re.findall(r"\d+", fields["steps"]):
        i = int(tok)
        if 1 <= i <= n_steps and i not in chosen:
            chosen.append(i)
    c.steps = chosen[:MAX_STEPS]
    c.ok = bool(c.what or c.why)
    return c

"""Turns a Finding into advice a non-expert can act on.

Order of operations (fast and safe first):
  1. 'safe' verdicts and low-severity spam never touch the LLM.
  2. quick(): a deterministic template answer, built instantly from the
     playbook. The app shows this at once.
  3. explain(): Llama writes a 2-sentence plain-language explanation from the
     evidence; the validator checks it; anything off falls back to the
     template text. On a Pi 4 this takes ~15-20 s with the persistent service,
     and is instant for alerts it has explained before.
The remediation steps always come verbatim from the playbook and are picked
by code, never by the LLM; the emergency step (call 1930) is always included.
"""
from dataclasses import dataclass, field, asdict

from .backends import TemplateBackend
from .playbooks import load_playbooks, get_playbook
from .prompt import build_prompt, max_new_tokens
from .validator import check_explanation

MAX_STEPS = 3
SKIP_LLM_SEVERITIES = {"low"}          # e.g. promo_spam: nothing to explain


@dataclass
class Advice:
    headline: str
    what: str
    why: str
    steps: list
    source: str                    # "llm" | "template" | "none"
    flags: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def pick_steps(book):
    """The first steps of the playbook (it lists them by priority), plus the 1930 step."""
    chosen = list(range(1, min(MAX_STEPS, len(book.steps)) + 1))
    chosen += [i for i, s in enumerate(book.steps, 1) if "1930" in s and i not in chosen]
    return [book.steps[i - 1] for i in chosen]


SAFE_ADVICE = dict(headline="LIKELY SAFE: no red flags found",
                   what="We found no warning signs in this message.",
                   why="It does not match the scam patterns we know.",
                   steps=["Stay careful: never share an OTP, PIN or password, whoever asks."])


class Advisor:
    def __init__(self, backend=None, playbooks=None):
        self.backend = backend or TemplateBackend()
        self.books = playbooks or load_playbooks()

    def needs_llm(self, finding):
        if finding.verdict == "safe" or isinstance(self.backend, TemplateBackend):
            return False
        return get_playbook(self.books, finding.category).severity not in SKIP_LLM_SEVERITIES

    def quick(self, finding):
        """Instant answer from the playbook. Never calls the LLM."""
        if finding.verdict == "safe":
            return Advice(source="none", **SAFE_ADVICE)
        book = get_playbook(self.books, finding.category)
        if finding.reasons:
            why = "Red flags: " + "; ".join(finding.reasons[:3]) + "."
        else:
            why = "It matches text patterns common in scam messages."
        return Advice(headline=f"{finding.verdict.upper()}: {book.title}", what=book.summary,
                      why=why, steps=pick_steps(book), source="template")

    def explain(self, finding):
        """Llama's explanation, validated; falls back to the template text."""
        base = self.quick(finding)
        if not self.needs_llm(finding):
            return base
        book = get_playbook(self.books, finding.category)
        n_examples = getattr(self.backend, "n_examples", None)
        prompt = (build_prompt(finding, book, n_examples) if n_examples is not None
                  else build_prompt(finding, book))
        res = self.backend.generate(prompt, max_new_tokens=max_new_tokens(finding.language))
        base.metrics = res.metrics
        if res.error or not res.text:
            base.flags.append(res.error or "no LLM output")
            return base

        checked = check_explanation(res.text, finding.verdict, finding.language)
        if not checked.ok:
            base.flags += checked.flags
            return base
        return Advice(headline=base.headline,
                      what=checked.what or base.what,
                      why=checked.why or base.why,
                      steps=base.steps, source="llm",
                      flags=checked.flags, metrics=res.metrics)

    def advise(self, finding):
        """Blocking version: the final answer (Llama's when available)."""
        return self.explain(finding)

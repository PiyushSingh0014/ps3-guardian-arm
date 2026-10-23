"""Turns a Finding into advice a non-expert can act on.

Order of operations (fast and safe first):
  1. 'safe' verdicts never touch the LLM.
  2. A deterministic template answer is built instantly from the playbook.
  3. Llama (through the backend) writes a friendlier explanation and picks steps.
  4. The validator checks that answer; anything off falls back to the template.
Step text always comes verbatim from the playbook, and the emergency step
(call 1930) is always included when the playbook has one.
"""
from dataclasses import dataclass, field, asdict

from .backends import TemplateBackend
from .playbooks import load_playbooks, get_playbook
from .prompt import build_prompt
from .validator import check_llm_output


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


def _with_emergency(book, chosen):
    must = [i for i, s in enumerate(book.steps, 1) if "1930" in s]
    return chosen + [i for i in must if i not in chosen]


def _default_steps(book):
    return list(range(1, min(3, len(book.steps)) + 1))


class Advisor:
    def __init__(self, backend=None, playbooks=None):
        self.backend = backend or TemplateBackend()
        self.books = playbooks or load_playbooks()

    def _template(self, finding, book):
        if finding.reasons:
            why = "Red flags: " + "; ".join(finding.reasons[:3]) + "."
        else:
            why = "It matches text patterns common in scam messages."
        idx = _with_emergency(book, _default_steps(book))
        return Advice(headline=f"{finding.verdict.upper()}: {book.title}", what=book.summary,
                      why=why, steps=[book.steps[i - 1] for i in idx], source="template")

    def advise(self, finding):
        if finding.verdict == "safe":
            return Advice(headline="LIKELY SAFE: no red flags found",
                          what="We found no warning signs in this message.",
                          why="It does not match the scam patterns we know.",
                          steps=["Stay careful: never share an OTP, PIN or password, whoever asks."],
                          source="none")

        book = get_playbook(self.books, finding.category)
        base = self._template(finding, book)
        res = self.backend.generate(build_prompt(finding, book))
        base.metrics = res.metrics
        if res.error or not res.text:
            base.flags.append(res.error or "no LLM output")
            return base

        checked = check_llm_output(res.text, finding.verdict, len(book.steps))
        if not checked.ok:
            base.flags += checked.flags
            return base

        idx = _with_emergency(book, checked.steps or _default_steps(book))
        return Advice(headline=base.headline,
                      what=checked.what or base.what,
                      why=checked.why or base.why,
                      steps=[book.steps[i - 1] for i in idx],
                      source="llm", flags=checked.flags, metrics=res.metrics)

"""Loads the remediation playbooks (advisor/playbooks/*.md).

Each playbook has a title, a severity, a one-line summary, numbered steps and
two lines that only Llama sees:
  pretends: who this kind of scam usually pretends to be (used when the
            detector cannot name the organisation)
  fact:     one checked fact Llama can rely on, so a 1B model does not have to
            remember how banks or couriers really behave.
Steps shown to users always come verbatim from here, never from the LLM.
"""
import os
import re
from dataclasses import dataclass, field

PLAYBOOK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")


@dataclass
class Playbook:
    key: str
    title: str
    severity: str
    summary: str
    steps: list = field(default_factory=list)
    pretends: str = ""
    fact: str = ""


def _parse(key, text):
    title = re.search(r"^#\s+(.+)$", text, re.M)
    severity = re.search(r"^severity:\s*(\w+)", text, re.M | re.I)
    summary = re.search(r"^summary:\s*(.+)$", text, re.M | re.I)
    pretends = re.search(r"^pretends:\s*(.+)$", text, re.M | re.I)
    fact = re.search(r"^fact:\s*(.+)$", text, re.M | re.I)
    block = text.split("## Steps", 1)[1] if "## Steps" in text else ""
    steps = [s.strip() for s in re.findall(r"^\s*\d+\.\s+(.+)$", block, re.M)]
    return Playbook(key=key,
                    title=title.group(1).strip() if title else key,
                    severity=severity.group(1).lower() if severity else "medium",
                    summary=summary.group(1).strip() if summary else "",
                    steps=steps,
                    pretends=pretends.group(1).strip() if pretends else "",
                    fact=fact.group(1).strip() if fact else "")


def load_playbooks(directory=PLAYBOOK_DIR):
    books = {}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".md"):
            with open(os.path.join(directory, name), encoding="utf-8") as f:
                books[name[:-3]] = _parse(name[:-3], f.read())
    if "generic_suspicious" not in books:
        raise RuntimeError("playbooks/generic_suspicious.md is required as the fallback")
    return books


def get_playbook(books, key):
    return books.get(key) or books["generic_suspicious"]

"""The one contract every detector emits.

SMS, URL, network-flow and DNS detectors all return a Finding. The fusion
engine and the Llama advisor only ever see Findings, so adding a new detector
never changes the advisor.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional

DANGEROUS_AT = 0.80
SUSPICIOUS_AT = 0.50


def verdict_from_score(score: float) -> str:
    if score >= DANGEROUS_AT:
        return "dangerous"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"


@dataclass
class Finding:
    source: str                      # "sms" | "url" | "flow" | "dns"
    verdict: str                     # "safe" | "suspicious" | "dangerous"
    score: float                     # calibrated probability of a threat, 0..1
    category: str                    # playbook key, e.g. "bank_kyc_scam"; "none" if safe
    reasons: list = field(default_factory=list)    # human-readable evidence
    entities: dict = field(default_factory=dict)   # e.g. {"sender": ..., "urls": [...]}
    raw_text: Optional[str] = None   # UNTRUSTED original content (e.g. the SMS body)
    language: str = "en"             # language for the explanation: "en" or "hi"

    def to_dict(self):
        return asdict(self)

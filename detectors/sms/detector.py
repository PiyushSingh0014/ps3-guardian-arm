"""SMS detector: message (+ optional sender) -> Finding.

Wraps the day-1 baseline (train_baseline.py + rules_india.py) behind the
common Finding contract. When you train a better model later, only this file
changes; the advisor and the API stay the same.
"""
import os
import sys
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:                 # lets the day-1 scripts keep their plain imports
    sys.path.insert(0, _HERE)

import joblib                                    # noqa: E402
import train_baseline as tb                      # noqa: E402
from brands import claimed_identity              # noqa: E402
from rules_india import TEN_DIGIT_RE, extract_signals, normalize_sender  # noqa: E402

from advisor.categorize import categorize_message    # noqa: E402
from advisor.findings import Finding, verdict_from_score  # noqa: E402


def sender_type(sender):
    if not sender:
        return "unknown"
    return "mobile_number" if TEN_DIGIT_RE.match(normalize_sender(sender)) else "sender_id"


class SmsDetector:
    def __init__(self, model_path=tb.MODEL):
        if not os.path.exists(model_path):
            print(f"[sms] no model at {model_path}; training on the bundled sample first")
            tb.train(tb.SAMPLE)
        bundle = joblib.load(model_path)
        self.clf, self.vec = bundle["clf"], bundle["vec"]

    def check(self, message: str, sender: Optional[str] = None, language: str = "en") -> Finding:
        x, _ = tb.build_features([message], vec=self.vec)     # cleans text internally
        score = float(self.clf.predict_proba(x)[0, 1])
        text = tb.clean_text(message)                       # same cleaning for the rules
        sig = extract_signals(text, sender=sender)
        verdict = verdict_from_score(score)
        if sig.has_apk and sig.has_url:          # an .apk link is near-certainly malicious
            verdict, score = "dangerous", max(score, 0.95)
        category = categorize_message(text, sig) if verdict != "safe" else "none"

        # claims_to_be (from a fixed list) and sender_type (one of three words) are
        # trusted, so the advisor may pass them to Llama. 'sender' is the raw value
        # typed or received; it is shown in the UI but never sent to Llama.
        entities = {"sender_type": sender_type(sender)}
        if sender:
            entities["sender"] = sender
        name, kind = claimed_identity(text, category)
        if name:
            entities["claims_to_be"], entities["claims_kind"] = name, kind
        return Finding(source="sms", verdict=verdict, score=round(score, 3), category=category,
                       reasons=list(sig.reasons), entities=entities,
                       raw_text=message, language=language)

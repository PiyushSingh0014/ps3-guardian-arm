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
from rules_india import extract_signals          # noqa: E402
from senders import apply_sender, classify_sender  # noqa: E402

from advisor.categorize import categorize_message    # noqa: E402
from advisor.findings import Finding, verdict_from_score  # noqa: E402
from detectors.files.names import APP_EXT, app_file_in_text  # noqa: E402


def sender_type(sender):
    """'mobile_number', 'registered_sender_id', 'other' or 'unknown'."""
    return classify_sender(sender).type_name


# How a checked link changes the odds that the message is fraud (detectors/url). Short
# links are left to the text model, which already has a feature for them.
LINK_ODDS = {"dangerous": 3.0, "suspicious": 1.5}
OFFICIAL_LINK_ODDS = 0.3        # every link in the message is on an official website
_GENERIC_LINK_REASONS = ("contains a link",
                         "claims to be from a bank, but the link is not on an official .bank.in website")


def _odds_times(p, k):
    p = min(max(p, 1e-6), 1 - 1e-6)
    o = p / (1 - p) * k
    return o / (1 + o)


def apply_links(score, links, sig):
    """Adjust a message score with its checked links (LinkVerdicts). Returns (score, decisive)."""
    if not links:
        return score, False
    if all(v.official for v in links):
        if any(r == _GENERIC_LINK_REASONS[1] for r in sig.reasons):
            sig.reasons.remove(_GENERIC_LINK_REASONS[1])       # the link is the bank's own site
        return _odds_times(score, OFFICIAL_LINK_ODDS), False
    risky = [v for v in links if v.verdict != "safe"]
    new = []
    for v in sorted(risky, key=lambda v: -v.score):
        for r in v.reasons[:2]:
            if r not in new and r not in sig.reasons and not (sig.has_apk and ".apk" in r):
                new.append(r)
    if new:                                    # link reasons first: they are the most specific
        sig.reasons[:] = new + [r for r in sig.reasons if r != _GENERIC_LINK_REASONS[0]]
    if any(v.decisive for v in links):
        return max(score, 0.95), True
    k = max([LINK_ODDS.get(v.verdict, 1.0) for v in risky if v.kind != "shortener"] or [1.0])
    return (_odds_times(score, k) if k != 1.0 else score), False


def decide(score, text, sender=None, use_sender=True, links=None):
    """Text score -> (final score, verdict, signals). Shared by the app and eval_india.py.

    The sender multiplies the odds of fraud (senders.py), then the links do (apply_links);
    an .apk link, a site on the phishing lists or a brand's name on someone else's site
    makes the message dangerous whoever sent it.
    """
    sig = extract_signals(text, sender=sender)
    if use_sender:
        score = apply_sender(score, classify_sender(sender), sig)
    score, decisive = apply_links(score, links, sig)
    verdict = verdict_from_score(score)
    if sig.has_apk and sig.has_url:          # an .apk link is near-certainly malicious
        verdict, score = "dangerous", max(score, 0.95)
    if decisive:
        verdict = "dangerous"
    return score, verdict, sig


V2_MODEL = os.path.join(_HERE, "sms_v2.joblib")     # train_v2.py --save; not in git


def model_score(p_fraud, p_normal, sender=None):
    """The text score decide() starts from. SMS model v2 tells fraud from genuine marketing, but
    in India only a registered sender ID (JD-HDFCBK-P) may send marketing (senders.py). So:
      - from a registered sender ID: the chance of fraud, and an offer is just an offer;
      - from a phone number, a chat or an unknown sender: the chance of fraud or marketing,
        as v1 scored every message: an "offer" from a personal number is not a genuine one.
    For v1, p_fraud is the chance of a threat and p_normal is 1 - p_fraud, so both give the same."""
    if classify_sender(sender).kind == "business":
        return float(p_fraud)
    return float(1.0 - p_normal)


def default_model():
    """GUARDIAN_SMS_MODEL if set; else SMS model v2 when it has been trained here; else v1."""
    return os.environ.get("GUARDIAN_SMS_MODEL") or (V2_MODEL if os.path.exists(V2_MODEL) else tb.MODEL)


ALLOW_SAMPLE = "GUARDIAN_ALLOW_SAMPLE_MODEL"     # tests set it to 1: the 30-message sample model


def sample_allowed():
    return os.environ.get(ALLOW_SAMPLE) == "1"


def load_model(model_path):
    """The model bundle. The app refuses a missing model, or one trained on the bundled 30-message
    sample, rather than run on a toy without anyone knowing; tests allow the sample."""
    if not os.path.exists(model_path):
        if not sample_allowed():
            raise RuntimeError(f"no SMS model at {model_path}. Train it first, on the Pi: python "
                               "detectors/sms/train_baseline.py --data ~/merged_sms.csv")
        if not os.path.exists(tb.SAMPLE_MODEL):
            print(f"[sms] no model at {model_path}; training the 30-message sample model ({ALLOW_SAMPLE}=1)")
            tb.train(tb.SAMPLE, out=tb.SAMPLE_MODEL)
        model_path = tb.SAMPLE_MODEL
    bundle = joblib.load(model_path)
    if bundle.get("data") == os.path.basename(tb.SAMPLE) and not sample_allowed():
        raise RuntimeError(f"{model_path} was trained on the 30-message sample, not real data. Train it again, "
                           "on the Pi: python detectors/sms/train_baseline.py --data ~/merged_sms.csv")
    return model_path, bundle


def model_info(model_path, bundle):
    """What the model learned from, for /health and the log; None where the bundle does not say
    (models trained before update 36)."""
    counts = bundle.get("trained_on")
    messages = bundle.get("messages") or (sum(counts.values()) if isinstance(counts, dict) else None)
    return {"version": int(bundle.get("version", 1)), "file": os.path.basename(model_path), "messages": messages,
            "data": bundle.get("data"), "date": bundle.get("date"),
            "features": len(getattr(bundle["vec"], "vocabulary_", {}) or {})}


class SmsDetector:
    """url_detector: "auto" checks links with detectors/url (model and lists when present),
    None skips them, or pass a UrlDetector."""

    def __init__(self, model_path=None, url_detector="auto"):
        model_path, bundle = load_model(model_path or default_model())
        self.clf, self.vec = bundle["clf"], bundle["vec"]
        # v1: two classes (threat or not). v2: three classes (fraud, marketing, normal), trained
        # with the team's messages too. model_score() turns either into the score decide() uses.
        self.version = int(bundle.get("version", 1))
        classes = list(self.clf.classes_)
        if self.version >= 2:
            self.fraud_col, self.normal_col = classes.index("fraud"), classes.index("normal")
        else:
            self.fraud_col, self.normal_col = classes.index(1), classes.index(0)
        self.model_name = f"v{self.version} ({os.path.basename(model_path)})"
        self.info = model_info(model_path, bundle)
        i = self.info
        print(f"[sms] model {self.model_name}: " + (f"{i['messages']:,} messages" if i["messages"] else
              "training size not recorded") + (f" from {i['data']}" if i["data"] else "")
              + (f", {i['date']}" if i["date"] else "") + f", {i['features']:,} features", flush=True)
        if url_detector == "auto":
            from detectors.url.detector import UrlDetector
            url_detector = UrlDetector()
        self.url = url_detector

    def text_probs(self, message: str):
        """(chance of fraud, chance of a normal message) for the text. v1: fraud means any threat."""
        x, _ = tb.build_features([message], vec=self.vec)     # cleans text internally
        p = self.clf.predict_proba(x)[0]
        return float(p[self.fraud_col]), float(p[self.normal_col])

    def text_score(self, message: str, sender: Optional[str] = None) -> float:
        """The model's score before the sender's odds and the links (model_score)."""
        return model_score(*self.text_probs(message), sender)

    def check(self, message: str, sender: Optional[str] = None, language: str = "en") -> Finding:
        return self._finding(message, sender, language, *self._prepare(message))

    def check_pair(self, message: str, sender: Optional[str] = None, language: str = "en"):
        """(with the sender, text only) for POST /sms: the text is scored and its links checked once."""
        prepared = self._prepare(message)
        return (self._finding(message, sender, language, *prepared),
                self._finding(message, None, language, *prepared))

    def _prepare(self, message):
        text = tb.clean_text(message)                       # same cleaning for the rules
        return text, (self.url.check_text(text) if self.url else []), self.text_probs(message)

    def _finding(self, message, sender, language, text, links, probs) -> Finding:
        score, verdict, sig = decide(model_score(*probs, sender), text, sender, links=links)
        category = categorize_message(text, sig) if verdict != "safe" else "none"
        if category in ("generic_suspicious", "promo_spam") and any(
                v.verdict != "safe" and v.kind not in ("shortener", "chat") for v in links):
            category = "phishing_link"

        # claims_to_be (from a fixed list) and sender_type (one of four words) are
        # trusted, so the advisor may pass them to Llama. 'sender' is the raw value
        # typed or received; it is shown in the UI but never sent to Llama.
        entities = {"sender_type": sender_type(sender)}
        if sender:
            entities["sender"] = sender
        name, kind = claimed_identity(text, category)
        imitated = next((v for v in links if v.imitates and v.verdict != "safe"), None)
        if not name and imitated:                  # the link's address names the brand
            name, kind = imitated.brand, imitated.brand_kind
        if name:
            entities["claims_to_be"], entities["claims_kind"] = name, kind
        if links:                                  # shown in the app, never sent to Llama
            entities["links"] = [{"link": v.shown(), "verdict": v.verdict, "kind": v.kind} for v in links[:5]]
        reasons = list(sig.reasons)
        app = app_file_in_text(message)            # "Wedding_Invitation.apk": the name a chat app shows
        if app:
            score, verdict, category = max(score, 0.97), "dangerous", "app_file"
            if not links:                          # an attachment, not a download link
                reasons = [r for r in reasons if "app file (.apk) from a link" not in r]
            reasons.insert(0, "the chat brought an Android app (APK) file, not a document or a photo" if app in APP_EXT
                           else "the chat brought a program file, not a document or a photo")
        return Finding(source="sms", verdict=verdict, score=round(score, 3), category=category,
                       reasons=reasons, entities=entities,
                       raw_text=message, language=language)

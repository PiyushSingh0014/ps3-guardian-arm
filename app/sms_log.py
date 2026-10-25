"""Log of the messages the Android companion forwards, for measuring the detector on real traffic.

One JSON line per message in logs/sms_traffic.jsonl (GUARDIAN_SMS_LOG overrides the path).
Each line says which phone it came from (the name typed in the app, for example "A") and
whether it was an SMS or a chat message (RCS, MMS or WhatsApp, read from a notification).
Privacy, because this file holds real messages:
  - every digit in the text is replaced by '#' (OTPs, account numbers, amounts);
  - a registered sender ID is kept (it names a business); a phone number is logged
    only as 'mobile', never with its digits; a chat sender's name only as 'name';
  - the text is not stored at all for a message from a phone number or an unknown
    sender that was judged safe, nor for any chat judged safe: that is mostly personal.
"""
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from detectors.sms.detector import classify_sender   # the detector module sets up its flat imports

DEFAULT_PATH = "logs/sms_traffic.jsonl"


def mask_digits(text):
    return re.sub(r"\d", "#", text or "")


def clean_device(name):
    """The phone's name as typed in the app, reduced to letters, digits, spaces, '_' and '-'."""
    return re.sub(r"[^A-Za-z0-9 _-]", "", name or "").strip()[:32] or None


class SmsLog:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("GUARDIAN_SMS_LOG", DEFAULT_PATH))
        self.lock = threading.Lock()

    def add(self, message, sender, finding, text_only, channel="sms", app=None, device=None):
        info = classify_sender(sender)
        if channel == "chat":
            # Chats carry a contact or brand name, or a phone number: never a registered ID.
            kind = "mobile" if info.kind == "mobile" else ("name" if (sender or "").strip() else "unknown")
            shown = kind
            keep_text = finding.verdict != "safe"
        else:
            kind = info.kind
            shown = info.header if info.kind == "business" else info.kind
            keep_text = info.kind in ("business", "other") or finding.verdict != "safe"
        entry = {
            "id": secrets.token_hex(6),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": clean_device(device),
            "channel": channel,
            "app": app if channel == "chat" else None,
            "sender": shown,
            "sender_kind": kind,
            "verdict": finding.verdict,
            "score": finding.score,
            "category": finding.category,
            "text_verdict": text_only.verdict,
            "text_score": text_only.score,
            "language": finding.language,
            "reasons": finding.reasons,
            "text": mask_digits(message) if keep_text else None,
        }
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry["id"]

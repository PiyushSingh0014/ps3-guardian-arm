"""Log of the messages the Android companion forwards, for measuring the detector on real traffic.

One JSON line per message in logs/sms_traffic.jsonl (GUARDIAN_SMS_LOG overrides the path).
Each line says which phone it came from (the name typed in the app, for example "A") and
whether it was an SMS or a chat message (RCS, MMS or WhatsApp, read from a notification).
Privacy, because this file holds real messages:
  - a message's text is kept only for study phones (data/sms/study.json): phones whose owners
    agreed to let the Pi keep texts for labelling. Other phones: time, sender kind, verdicts;
  - in the text, every digit is replaced by '#' (OTPs, account numbers, amounts);
  - a registered sender ID is kept (it names a business); a phone number is logged
    only as 'mobile', never with its digits; a chat sender's name only as 'name';
  - even for study phones, the text is not stored for a message from a phone number or an
    unknown sender that was judged safe, nor for any chat judged safe: that is mostly personal.
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
STUDY_PATH = os.path.join("data", "sms", "study.json")
STUDY_NOTE = ("Phones whose owners agreed to let the Pi keep message texts, digits masked, for labelling "
              "(app/sms_log.py). Remove a name to stop; add one only with its owner's agreement. "
              "'-' is a phone without a name; '*' is every phone.")


class StudyPhones:
    """The study phones in data/sms/study.json (GUARDIAN_STUDY overrides the path), re-read when the
    file changes. Created once with the phones already in the log: their owners agreed before."""

    def __init__(self, path=None, log_path=None):
        self.path = Path(path or os.environ.get("GUARDIAN_STUDY", STUDY_PATH))
        self.log_path, self.mtime, self.names = log_path, None, set()
        self.lock = threading.Lock()

    def _create(self):
        names = set()
        if self.log_path and Path(self.log_path).exists():
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        names.add(json.loads(line).get("device") or "-")
                    except ValueError:
                        continue
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"phones": sorted(names), "note": STUDY_NOTE}, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
        print(f"[sms] study phones: created {self.path} with the phones already in the log: "
              f"{', '.join(sorted(names)) or 'none'}", flush=True)

    def includes(self, phone):
        with self.lock:
            if not self.path.exists():
                self._create()
            mtime = self.path.stat().st_mtime
            if mtime != self.mtime:
                try:
                    self.names = {str(p) for p in json.loads(self.path.read_text(encoding="utf-8")).get("phones", [])}
                except (OSError, ValueError, AttributeError) as e:
                    print(f"[sms] cannot read {self.path} ({e}): no texts are kept until it is fixed", flush=True)
                    self.names = set()
                self.mtime = mtime
            return "*" in self.names or (phone or "-") in self.names


def mask_digits(text):
    return re.sub(r"\d", "#", text or "")


def clean_device(name):
    """The phone's name as typed in the app, reduced to letters, digits, spaces, '_' and '-'."""
    return re.sub(r"[^A-Za-z0-9 _-]", "", name or "").strip()[:32] or None


class SmsLog:
    def __init__(self, path=None, study=None):
        self.path = Path(path or os.environ.get("GUARDIAN_SMS_LOG", DEFAULT_PATH))
        self.lock = threading.Lock()
        self.study = study or StudyPhones(log_path=self.path)

    def add(self, message, sender, finding, text_only, channel="sms", app=None, device=None):
        info = classify_sender(sender)
        phone = clean_device(device)
        study = self.study.includes(phone or "-")
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
            "device": phone,
            "study": study,
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
            "text": mask_digits(message) if keep_text and study else None,
        }
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry["id"]

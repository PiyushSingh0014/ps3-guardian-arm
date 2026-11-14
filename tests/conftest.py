"""Shared test set-up:
  - every test uses the SMS model trained on the 30-message sample (detectors/sms/sms_sample.joblib),
    the same on every machine; only tests may use it (GUARDIAN_ALLOW_SAMPLE_MODEL). These settings are
    made when this file loads, before any test module is imported: some build a detector at import;
  - every request carries a test pairing token (tests/auth.py), and every phone is a study phone;
  - no test writes the Pi's real watch list of scam links, its log of lab tests, its log of checked
    files or its list of study phones."""
import json
import os
import tempfile

import pytest

from tests.auth import TOKEN

SAMPLE_MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "detectors", "sms", "sms_sample.joblib")
STUDY = os.path.join(tempfile.mkdtemp(prefix="ps3-test-study-"), "study.json")
with open(STUDY, "w", encoding="utf-8") as f:
    json.dump({"phones": ["*"]}, f)
os.environ.update(GUARDIAN_SMS_MODEL=SAMPLE_MODEL, GUARDIAN_ALLOW_SAMPLE_MODEL="1", GUARDIAN_TOKEN=TOKEN,
                  GUARDIAN_STUDY=STUDY)
os.environ.pop("GUARDIAN_DEVICE_TOKEN", None)


@pytest.fixture(autouse=True)
def _watch_list_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("NET_WATCH", str(tmp_path / "watch.json"))
    monkeypatch.setenv("LAB_TESTS", str(tmp_path / "lab_tests.jsonl"))
    monkeypatch.setenv("FILE_LOG", str(tmp_path / "file_checks.jsonl"))

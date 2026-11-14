"""Shared test set-up: no test writes the Pi's real watch list of scam links, its log of lab tests or
its log of checked files, and every test uses SMS model v1, even on a Pi where v2 has been trained
(detectors/sms/sms_v2.joblib)."""
import os

import pytest

V1_MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "detectors", "sms", "sms_baseline.joblib")


@pytest.fixture(autouse=True)
def _watch_list_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("NET_WATCH", str(tmp_path / "watch.json"))
    monkeypatch.setenv("LAB_TESTS", str(tmp_path / "lab_tests.jsonl"))
    monkeypatch.setenv("FILE_LOG", str(tmp_path / "file_checks.jsonl"))
    monkeypatch.setenv("GUARDIAN_SMS_MODEL", V1_MODEL)

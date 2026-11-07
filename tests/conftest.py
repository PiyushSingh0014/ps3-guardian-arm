"""Shared test set-up: no test writes the Pi's real watch list of scam links, its log of lab tests or
its log of checked files."""
import pytest


@pytest.fixture(autouse=True)
def _watch_list_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("NET_WATCH", str(tmp_path / "watch.json"))
    monkeypatch.setenv("LAB_TESTS", str(tmp_path / "lab_tests.jsonl"))
    monkeypatch.setenv("FILE_LOG", str(tmp_path / "file_checks.jsonl"))

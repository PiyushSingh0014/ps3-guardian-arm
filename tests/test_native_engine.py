"""NativeLlamaEngine (the Python side of deploy/advisor_server), against a fake server.

The fake server speaks the same stdin/stdout protocol as the C++ binary and
uses the same fake model as test_engine_service.py, so the answers must match
the in-process engine exactly.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

from advisor.backends import LlamaServiceBackend
from advisor.llm_native import NativeLlamaEngine, NativeServerError
from advisor.llm_service import IdleRewarmer, create_app
from tests.fakes import make_engine

FAKE = [sys.executable, os.path.join(os.path.dirname(__file__), "fake_advisor_server.py")]
PREFIX = "fixed system text and worked examples | "


@pytest.fixture
def native():
    e = NativeLlamaEngine(FAKE, "model.pte", "tokenizer.model", threads=3)
    yield e
    e.close()


def test_start_reports_the_model_bounds(native):
    assert native.threads == 3 and native.max_context_len == 200 and native.max_tokens_per_call == 7


def test_same_answers_as_the_in_process_engine(native):
    local = make_engine()
    for prompt in (PREFIX + "alert one", PREFIX + "alert two!", PREFIX + "alert one"):
        assert native.generate(prompt, 12)[0] == local.generate(prompt, 12)[0]


def test_prefix_reuse_check_and_reset(native):
    native.prefill(PREFIX)
    assert native.is_resident(PREFIX) and native.kv_tokens == len(PREFIX)
    _, m = native.generate(PREFIX + "alert", 5)
    assert m["reused_tokens"] == len(PREFIX) and m["engine"] == "native"
    native.reset()
    assert native.kv_tokens == 0 and not native.is_resident(PREFIX)


def test_bad_request_is_a_value_error(native):
    with pytest.raises(ValueError):
        native.generate("z" * 300, 8)                 # longer than the context
    assert native.generate("ok", 2)[1]["generated_tokens"] <= 2   # still usable afterwards


def test_start_failure_is_reported(monkeypatch):
    monkeypatch.setenv("FAKE_SERVER_FAIL_START", "1")
    with pytest.raises(NativeServerError, match="could not load tokenizer"):
        NativeLlamaEngine(FAKE, "model.pte", "tokenizer.model")


def test_illegal_instruction_is_explained(monkeypatch):
    monkeypatch.setenv("FAKE_SERVER_CRASH_ON", "GEN")
    e = NativeLlamaEngine(FAKE, "model.pte", "tokenizer.model")
    with pytest.raises(NativeServerError, match="SIGILL"):
        e.generate(PREFIX, 4)
    with pytest.raises(NativeServerError):          # later calls fail fast, no hang
        e.generate(PREFIX, 4)


def test_service_and_rewarm_with_the_native_engine(native):
    backend = LlamaServiceBackend(client=TestClient(create_app(native, None, model_id="m")))
    res = backend.generate(PREFIX + "alert", max_new_tokens=6)
    assert res.text and not res.error and res.metrics["engine"] == "native"
    health = backend.health()
    assert health["ok"] and health["engine"] == "NativeLlamaEngine" and health["kv_tokens"] > 0
    rw = IdleRewarmer(native, PREFIX + "en", idle_s=0)
    assert rw.tick() is True and native.is_resident(PREFIX + "en") and rw.tick() is False

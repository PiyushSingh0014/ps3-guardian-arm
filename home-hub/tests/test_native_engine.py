"""NativeLlamaEngine (the Python side of llama-engine/advisor_server), against a fake server.

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
    assert native.prefill_chunk == 7


def test_same_answers_as_the_in_process_engine(native):
    local = make_engine()
    for prompt in (PREFIX + "alert one", PREFIX + "alert two!", PREFIX + "alert one"):
        (t1, m1), (t2, m2) = native.generate(prompt, 12), local.generate(prompt, 12)
        assert t1 == t2 and m1["logits_crc32"] == m2["logits_crc32"]


def test_piece_size_is_passed_to_the_server():
    e = NativeLlamaEngine(FAKE, "model.pte", "tokenizer.model", prefill_chunk=0)
    try:
        assert e.prefill_chunk == 0
        local = make_engine(prefill_chunk=0)
        e.prefill(PREFIX)
        local.prefill(PREFIX)
        (t1, m1), (t2, m2) = e.generate(PREFIX + "alert", 8), local.generate(PREFIX + "alert", 8)
        assert t1 == t2 and m1["logits_crc32"] == m2["logits_crc32"] and m1["prefill_calls"] == 1
    finally:
        e.close()


def test_prefix_reuse_check_and_reset(native):
    native.prefill(PREFIX)
    grid = len(PREFIX) // 7 * 7
    assert native.is_resident(PREFIX) and native.kv_tokens == grid
    _, m = native.generate(PREFIX + "alert", 5)
    assert m["reused_tokens"] == grid and m["engine"] == "native"
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

"""The persistent Llama engine and service, tested with a fake model (no torch needed).

The fake model keeps its own KV cache and makes every next token depend on the
whole visible context, so any position or prefix-reuse mistake in the engine
changes the output and fails these tests. (The engine was also checked against
ExecuTorch itself with a tiny exported Llama; see README.md.)
"""
from fastapi.testclient import TestClient

from advisor.backends import LlamaServiceBackend
from advisor.llm_engine import common_prefix_len
from advisor.llm_service import AnswerCache, IdleRewarmer, create_app
from tests.fakes import EOS, make_engine

def engine(**kw):
    return make_engine(**kw)


PREFIX = "fixed system text and worked examples | "


def test_reads_bounds_from_the_program():
    e = engine(max_call=7, context=200)
    assert e.max_tokens_per_call == 7 and e.max_context_len == 200 and EOS in e.eos_ids


def test_prefix_reuse_gives_the_same_answer_as_a_fresh_engine():
    warm = engine()
    warm.prefill(PREFIX)
    a1, m1 = warm.generate(PREFIX + "alert one", 12)
    b1, m2 = warm.generate(PREFIX + "alert two!", 12)
    assert m1["reused_tokens"] == len(PREFIX) and m1["prefill_tokens"] == len("alert one")
    assert m2["reused_tokens"] >= len(PREFIX)
    a2, _ = engine().generate(PREFIX + "alert one", 12)
    b2, _ = engine().generate(PREFIX + "alert two!", 12)
    assert (a1, b1) == (a2, b2)


def test_exact_repeat_reads_one_token():
    e = engine()
    t1, _ = e.generate(PREFIX + "same", 10)
    t2, m = e.generate(PREFIX + "same", 10)
    assert t1 == t2 and m["prefill_tokens"] == 1


def test_long_prompt_is_chunked_within_the_bound():
    e = engine(max_call=7)
    e.prefill("x" * 30)
    assert [n for _, n in e.module.calls] == [7, 7, 7, 7, 2]
    assert [p for p, _ in e.module.calls] == [0, 7, 14, 21, 28]


def test_context_limit_max_tokens_and_eos():
    e = engine(context=50)
    try:
        e.generate("y" * 45, 10)
        raise AssertionError("should refuse a prompt that cannot fit")
    except ValueError:
        pass
    assert engine(eos_after=10).generate("abc", 40)[1]["generated_tokens"] == 7   # stops at EOS
    assert engine(eos_after=999).generate("abc", 5)[1]["generated_tokens"] == 5   # stops at the cap


def test_common_prefix_len():
    assert common_prefix_len([1, 2, 3], [1, 2, 4]) == 2
    assert common_prefix_len([], [1]) == 0


# --- service ------------------------------------------------------------------
def test_service_generate_cache_and_health(tmp_path):
    cache = AnswerCache(str(tmp_path / "answers.jsonl"))
    client = TestClient(create_app(engine(), cache, model_id="m"))
    r1 = client.post("/generate", json={"prompt": PREFIX + "hello", "max_new_tokens": 8}).json()
    r2 = client.post("/generate", json={"prompt": PREFIX + "hello", "max_new_tokens": 8}).json()
    assert r1["metrics"]["cached"] is False and r2["metrics"]["cached"] is True
    assert r1["text"] == r2["text"]
    assert len(AnswerCache(str(tmp_path / "answers.jsonl"))) == 1          # survives a restart
    h = client.get("/health").json()
    assert h["ok"] and h["requests"] == 1 and h["answer_cache_items"] == 1
    assert client.post("/prefill", json={"prompt": PREFIX}).status_code == 200
    too_long = client.post("/generate", json={"prompt": "z" * 300, "max_new_tokens": 8})
    assert too_long.status_code == 400


def test_backend_talks_to_service():
    backend = LlamaServiceBackend(client=TestClient(create_app(engine(), None, model_id="m")))
    res = backend.generate(PREFIX + "alert", max_new_tokens=6)
    assert res.text and not res.error and res.metrics["generated_tokens"] <= 6
    assert backend.health()["ok"]


def test_backend_reports_unreachable_service():
    res = LlamaServiceBackend(url="http://127.0.0.1:9", timeout_s=2).generate("x")
    assert res.error.startswith("Llama service not reachable")


def test_idle_rewarm_restores_the_default_prefix():
    e = engine()
    rw = IdleRewarmer(e, PREFIX + "en", idle_s=0)
    e.prefill(PREFIX + "en")
    assert rw.tick() is False                      # already warm
    e.generate("a different language prefix", 4)
    assert not e.is_resident(PREFIX + "en")
    assert rw.tick() is True and e.is_resident(PREFIX + "en")


def test_reset_forgets_the_cache():
    e = engine()
    e.prefill(PREFIX)
    assert e.kv_tokens == len(PREFIX)
    e.reset()
    assert e.kv_tokens == 0 and e.generate(PREFIX + "x", 3)[1]["reused_tokens"] == 0

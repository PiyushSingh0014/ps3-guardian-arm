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
    assert e.prefill_chunk == 7                   # the 32-token grid is capped at the call bound


GRID = len(PREFIX) // 7 * 7                       # last full 7-token piece of the prefix


def test_prefix_reuse_gives_the_same_answer_as_a_fresh_engine():
    warm = engine()
    warm.prefill(PREFIX)
    a1, m1 = warm.generate(PREFIX + "alert one", 12)
    b1, m2 = warm.generate(PREFIX + "alert two!", 12)
    assert m1["reused_tokens"] == GRID and m1["prefill_tokens"] == len(PREFIX + "alert one") - GRID
    assert m2["reused_tokens"] >= GRID
    a2, n1 = engine().generate(PREFIX + "alert one", 12)
    b2, n2 = engine().generate(PREFIX + "alert two!", 12)
    assert (a1, b1) == (a2, b2)
    assert (m1["logits_crc32"], m2["logits_crc32"]) == (n1["logits_crc32"], n2["logits_crc32"])


def test_answer_depends_only_on_the_prompt():
    target = PREFIX + "alert one"
    fresh = engine().generate(target, 12)
    histories = [[("prefill", PREFIX)], [("gen", PREFIX + "alert two!")], [("gen", PREFIX + "alert on")],
                 [("gen", target)], [("gen", "unrelated"), ("prefill", PREFIX[:20])],
                 [("prefill", PREFIX), ("gen", PREFIX + "alert one more"), ("gen", "x" * 50)]]
    for history in histories:
        e = engine()
        for kind, p in history:
            e.prefill(p) if kind == "prefill" else e.generate(p, 5)
        text, m = e.generate(target, 12)
        assert (text, m["logits_crc32"]) == (fresh[0], fresh[1]["logits_crc32"]), history


def test_without_the_grid_the_cache_history_can_change_the_answer():
    """What the Raspberry Pi 4 showed: same prompt, different words after a warm-up."""
    target = PREFIX + "alert one"
    fresh = engine(prefill_chunk=0).generate(target, 12)[0]
    warm = engine(prefill_chunk=0)
    warm.prefill(PREFIX)
    _, m = warm.generate(target, 12)
    assert m["reused_tokens"] == len(PREFIX) and m["prefill_calls"] == 2   # fewer calls, but...
    assert warm.generate(target, 12)[0] != fresh


def test_exact_repeat_rereads_only_the_last_piece():
    e = engine()
    t1, m1 = e.generate(PREFIX + "same", 10)
    t2, m2 = e.generate(PREFIX + "same", 10)
    n = len(PREFIX + "same")
    assert t1 == t2 and m1["logits_crc32"] == m2["logits_crc32"]
    assert m2["reused_tokens"] == (n - 1) // 7 * 7 and m2["prefill_tokens"] == n - (n - 1) // 7 * 7


def test_prompt_is_read_in_fixed_pieces():
    e = engine(max_call=7)
    e.prefill("x" * 30)                           # a warm-up stops at the last full piece
    assert e.module.calls == [(0, 7), (7, 7), (14, 7), (21, 7)] and e.kv_tokens == 28
    e.module.calls.clear()
    e.generate("x" * 30 + "y" * 10, 1)
    assert e.module.calls == [(28, 7), (35, 5)]
    old = engine(max_call=7, prefill_chunk=0)     # without the grid: fewest calls within the bound
    old.prefill("x" * 30)
    assert old.module.calls == [(0, 7), (7, 7), (14, 7), (21, 7), (28, 2)]


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
    assert e.kv_tokens == GRID
    e.reset()
    assert e.kv_tokens == 0 and e.generate(PREFIX + "x", 3)[1]["reused_tokens"] == 0

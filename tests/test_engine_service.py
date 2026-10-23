"""The persistent Llama engine and service, tested with a fake model (no torch needed).

The fake model keeps its own KV cache and makes every next token depend on the
whole visible context, so any position or prefix-reuse mistake in the engine
changes the output and fails these tests. (The engine was also checked against
ExecuTorch itself with a tiny exported Llama; see README.md.)
"""
from fastapi.testclient import TestClient

from advisor.backends import LlamaServiceBackend
from advisor.llm_engine import LlamaEngine, common_prefix_len
from advisor.llm_service import AnswerCache, IdleRewarmer, create_app

EOS = 3


class _Sizes:
    def __init__(self, n):
        self.n = n

    def sizes(self):
        return (1, self.n)


class _Meta:
    def __init__(self, n):
        self.n = n

    def input_tensor_meta(self, i):
        return _Sizes(self.n)


class FakeModule:
    """Mimics the ExecuTorch module API the engine uses."""

    def __init__(self, max_call=7, context=200, eos_after=None):
        self.kv, self.calls = {}, []
        self.max_call, self.context, self.eos_after = max_call, context, eos_after

    def method_names(self):
        return ["forward", "get_max_seq_len", "get_max_context_len", "get_eos_ids", "enable_dynamic_shape"]

    def run_method(self, name, inputs):
        return {"get_max_seq_len": [self.max_call + 1], "get_max_context_len": [self.context],
                "get_eos_ids": [EOS], "enable_dynamic_shape": [True]}[name]

    def method_meta(self, name):
        return _Meta(self.max_call)

    def step(self, ids, pos):
        assert 1 <= len(ids) <= self.max_call, "chunk larger than the exported bound"
        for i, t in enumerate(ids):
            self.kv[pos + i] = t
        h = 7
        for p in range(pos + len(ids)):            # depends on every visible position
            h = (h * 31 + self.kv[p]) % 1_000_003
        self.calls.append((pos, len(ids)))
        if self.eos_after is not None:                 # deterministic end, for the EOS test
            return EOS if pos + len(ids) >= self.eos_after else 10 + h % 40
        return EOS if h % 17 == 0 else 10 + h % 40


class FakeTokenizer:
    eos_id, n_words = EOS, 60

    def encode(self, s, bos=False, eos=False, allowed_special=None):
        return [10 + (ord(c) % 40) for c in s]

    def decode(self, ids):
        return "".join(chr(ord("a") + (i - 10) % 26) for i in ids)


class FakeEngine(LlamaEngine):
    def _forward(self, ids, pos):
        return self.module.step(ids, pos)

    @staticmethod
    def _argmax(token):
        return token


def engine(**kw):
    return FakeEngine(module=FakeModule(**kw), tokenizer=FakeTokenizer(), threads=1)


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
    assert rw.tick() is True and e.kv[:len(rw.ids)] == rw.ids

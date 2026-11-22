"""Fake model pieces shared by the engine tests and tests/fake_advisor_server.py.

The fake model keeps its own KV cache and makes every next token depend on the
whole visible context, so any position or prefix-reuse mistake in an engine
changes the output. Like the real kernels, it also depends on how the prompt was
split into calls: each cache entry remembers the call that computed it, the way
float rounding in the real attention kernel depends on the call's length.
"""
from advisor.llm_engine import LlamaEngine

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
            self.kv[pos + i] = (t, pos, pos + len(ids))   # token + the call that computed it
        h = 7
        for p in range(pos + len(ids)):            # depends on every visible position
            t, start, end = self.kv[p]
            h = (h * 31 + t + 101 * start + 1009 * end) % 1_000_003
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

    @staticmethod
    def _logits_bytes(token):
        return str(token).encode()


def make_engine(prefill_chunk=32, **kw):
    return FakeEngine(module=FakeModule(**kw), tokenizer=FakeTokenizer(), threads=1,
                      prefill_chunk=prefill_chunk)

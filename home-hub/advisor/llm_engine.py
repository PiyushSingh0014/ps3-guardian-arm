"""Llama 3.2 on ExecuTorch, loaded once, with KV-cache prefix reuse.

Why this exists: `llama_main` loads the 1 GB model (~12 s on a Pi 4) and
re-reads the whole prompt for every alert. This engine keeps the model in
memory and remembers which tokens are already in its KV cache. Every advisor
prompt starts with the same fixed prefix (system text + worked examples), so
for a new alert only the tokens after the longest common prefix are read.

It calls the exported program's `forward(tokens, input_pos)` directly
through the ExecuTorch Python runtime (the same kernels and XNNPACK delegate
llama_main uses), so we choose the KV-cache position ourselves:

    KV cache:  [ fixed prefix | alert 1 + answer ]     after alert 1
    KV cache:  [ fixed prefix | alert 2 ...        ]   alert 2 starts writing at
                                                       the end of the prefix
Entries after the current position are never attended to (causal attention
over positions < input_pos + n), so old alert tokens do not leak into the
next answer; they are simply overwritten.

Fixed prefill grid. A forward call's results depend slightly on how the
prompt was split into calls: the attention kernel's matrix blocking follows
the call's length, so the same token can get differently rounded keys and
values. On a Raspberry Pi 4 this changed a word in an answer. So prompts are
always read in pieces of `prefill_chunk` tokens at fixed positions (0, 32,
64, ...), and the cache is reused only up to such a boundary. Every position
is then computed by exactly the same calls whatever was cached before, and an
answer depends only on its prompt (checked bit for bit with `logits_crc32`).

Needs (not on a Pi 4, which uses llama-engine/advisor_server instead): torch (CPU
build) and executorch, the same version as the one you exported with.
"""
import glob
import os
import threading
import time
import zlib

LLAMA3_EOS = {128001, 128008, 128009}   # <|end_of_text|>, <|eom_id|>, <|eot_id|>


def _register_kernels():
    """Load the custom LLM ops (sdpa + KV-cache update) and quantized kernels into
    the ExecuTorch runtime. The .pte from export_llm needs both."""
    import torch
    from executorch.extension.pybindings import portable_lib  # noqa: F401  (runtime first)
    import executorch.extension.llm.custom_ops as custom_ops_pkg
    import executorch.kernels.quantized  # noqa: F401  (registers quantized_decomposed::*)

    libs = glob.glob(os.path.join(os.path.dirname(custom_ops_pkg.__file__), "*custom_ops_aot_lib.*"))
    if libs:
        torch.ops.load_library(libs[0])
    else:                                   # older layouts: let the module find it
        from executorch.extension.llm.custom_ops import custom_ops  # noqa: F401
    return portable_lib


def load_tokenizer(path):
    """Llama 3 tiktoken tokenizer (the same tokenizer.model llama_main uses)."""
    from pytorch_tokenizers.tiktoken import TiktokenTokenizer
    return TiktokenTokenizer(model_path=str(path))


def common_prefix_len(a, b):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def grid_plan(n, lcp, exact, chunk, prefill_only):
    """(reuse, end) for a prompt of n tokens: keep cache positions < reuse, compute
    positions reuse..end-1. Shared by both engines and the tests.

    With a grid (chunk > 0) reuse is a grid boundary that every earlier call
    computed exactly (exact = tokens covered by full grid pieces), and a prefill
    without generation stops at the last full piece: a partial piece is never
    reused, so computing it would be wasted. Without a grid, reuse the whole
    common prefix and read the rest in as few calls as possible."""
    if chunk > 0:
        limit = n if prefill_only else n - 1          # generation needs >= 1 fresh token
        reuse = min(lcp, limit, exact) // chunk * chunk
        return reuse, (n // chunk * chunk if prefill_only else n)
    return min(lcp, n - 1), n


class LlamaEngine:
    def __init__(self, pte_path=None, tokenizer_path=None, threads=4, module=None, tokenizer=None,
                 prefill_chunk=32):
        t0 = time.perf_counter()
        if module is None:
            portable_lib = _register_kernels()
            if threads:
                portable_lib._unsafe_reset_threadpool(int(threads))
            module = portable_lib._load_for_executorch(str(pte_path))
            self.threads = portable_lib._threadpool_get_thread_count()
        else:
            self.threads = threads
        self.module = module
        self.tok = tokenizer if tokenizer is not None else load_tokenizer(tokenizer_path)
        self.load_s = round(time.perf_counter() - t0, 3)

        meta = self._metadata()
        self.max_seq_len = int(meta.get("get_max_seq_len", 128))
        self.max_context_len = int(meta.get("get_max_context_len", self.max_seq_len))
        self.dynamic_shape = bool(meta.get("enable_dynamic_shape", True))
        try:    # the exported token dimension bounds one forward call (export uses max_seq_len - 1)
            self.max_tokens_per_call = int(self.module.method_meta("forward").input_tensor_meta(0).sizes()[1])
        except Exception:
            self.max_tokens_per_call = self.max_seq_len - 1 if self.dynamic_shape else 1
        eos = meta.get("get_eos_ids")
        eos = set(eos if isinstance(eos, (list, tuple)) else [eos]) if eos is not None else set()
        self.eos_ids = {int(e) for e in eos} | {int(self.tok.eos_id)} | (
            LLAMA3_EOS if self.tok.n_words > 128009 else set())
        self.prefill_chunk = min(int(prefill_chunk), self.max_tokens_per_call) if prefill_chunk and prefill_chunk > 0 else 0
        self.kv = []            # token ids whose keys/values are in the cache, positions 0..len-1
        self.exact = 0          # leading cache positions computed by full grid pieces
        self.lock = threading.RLock()   # re-entrant: the idle re-warmer holds it while calling prefill()
        self.stats = {"requests": 0, "prompt_tokens": 0, "reused_tokens": 0}

    # -- model access ---------------------------------------------------------
    def _metadata(self):
        names = set(self.module.method_names())
        meta = {}
        for name in ("get_max_seq_len", "get_max_context_len", "enable_dynamic_shape",
                     "get_eos_ids", "get_bos_id", "get_vocab_size", "use_kv_cache"):
            if name in names:
                out = self.module.run_method(name, ())
                meta[name] = out[0] if len(out) == 1 else list(out)
        return meta

    def _forward(self, ids, pos):
        import torch
        out = self.module.forward((torch.tensor([ids], dtype=torch.long),
                                   torch.tensor([pos], dtype=torch.long)))[0]
        if out.dim() == 3:          # [1, seq, vocab] when the export keeps all logits
            out = out[0, -1]
        elif out.dim() == 2:        # [1, vocab]
            out = out[-1]
        return out

    @staticmethod
    def _argmax(logits):
        return int(logits.argmax().item())

    @staticmethod
    def _logits_bytes(logits):
        return logits.detach().contiguous().float().numpy().tobytes()

    # -- public API -----------------------------------------------------------
    def encode(self, prompt):
        # allowed_special="all": the advisor prompt uses Llama 3 chat tokens. All text in
        # it is trusted (v3 never includes the message), and prompt.py strips any
        # "<|...|>" pattern from fields anyway.
        return self.tok.encode(prompt, bos=False, eos=False, allowed_special="all")

    def generate(self, prompt, max_new_tokens=64, on_token=None):
        """Greedy (temperature 0) generation with prefix reuse. Returns (text, metrics).
        metrics["logits_crc32"] covers the logits behind every generated token, so two
        runs with the same value computed bit-identical answers."""
        return self._run(prompt, max_new_tokens, on_token, prefill_only=False)

    def prefill(self, prompt):
        """Read a prompt into the KV cache without generating (used to warm the fixed prefix)."""
        return self._run(prompt, 0, None, prefill_only=True)[1]

    def _run(self, prompt, max_new_tokens, on_token, prefill_only):
        with self.lock:
            t0 = time.perf_counter()
            ids = self.encode(prompt)
            if not ids:
                raise ValueError("empty prompt")
            if len(ids) + max_new_tokens > self.max_context_len:
                raise ValueError(f"prompt ({len(ids)} tokens) + {max_new_tokens} new tokens "
                                 f"exceeds the model context ({self.max_context_len})")
            reuse, end = grid_plan(len(ids), common_prefix_len(self.kv, ids), self.exact,
                                   self.prefill_chunk, prefill_only)
            del self.kv[reuse:]
            self.exact = min(self.exact, reuse)
            t_tok = time.perf_counter()

            step = self.prefill_chunk or max(1, self.max_tokens_per_call)
            pos, logits, calls = reuse, None, 0
            for i in range(reuse, end, step):
                chunk = ids[i:min(i + step, end)]
                logits = self._forward(chunk, pos)
                pos += len(chunk)
                calls += 1
                self.kv.extend(chunk)
            self.exact = end // self.prefill_chunk * self.prefill_chunk if self.prefill_chunk else end
            t_prefill = time.perf_counter()

            out, n_decode, crc = [], 0, 0
            if not prefill_only:
                crc = zlib.crc32(self._logits_bytes(logits))
                nxt = self._argmax(logits)
                while nxt not in self.eos_ids and len(out) < max_new_tokens:
                    out.append(nxt)
                    if on_token:
                        on_token(nxt)
                    if len(out) == max_new_tokens:
                        break
                    logits = self._forward([nxt], pos)
                    crc = zlib.crc32(self._logits_bytes(logits), crc)
                    self.kv.append(nxt)
                    pos += 1
                    n_decode += 1
                    nxt = self._argmax(logits)
            t_end = time.perf_counter()

        prefill_s, decode_s = t_prefill - t_tok, t_end - t_prefill
        n_prefill = end - reuse
        if not prefill_only:
            self.stats["requests"] += 1
            self.stats["prompt_tokens"] += len(ids)
            self.stats["reused_tokens"] += reuse
        metrics = {
            "prompt_tokens": len(ids), "reused_tokens": reuse, "prefill_tokens": n_prefill,
            "prefill_calls": calls, "prefill_chunk": self.prefill_chunk,
            "generated_tokens": len(out),
            "ttft_s": round(t_prefill - t0, 3),
            "prefill_s": round(prefill_s, 3), "decode_s": round(decode_s, 3),
            "prefill_tok_s": round(n_prefill / prefill_s, 2) if n_prefill and prefill_s > 0 else None,
            "decode_tok_s": round(n_decode / decode_s, 2) if n_decode and decode_s > 0 else None,
            "total_s": round(t_end - t0, 3),
            "logits_crc32": None if prefill_only else f"{crc:08x}",
        }
        return self.tok.decode(out), {k: v for k, v in metrics.items() if v is not None}

    def is_resident(self, prompt):
        """True if a prefill of `prompt` would read nothing new: the next prompt that
        starts with it reuses everything a fresh run would compute the same way."""
        with self.lock:
            ids = self.encode(prompt)
            lcp = common_prefix_len(self.kv, ids)
            if self.prefill_chunk:
                return min(lcp, self.exact) >= len(ids) // self.prefill_chunk * self.prefill_chunk
            return lcp >= len(ids)

    def reset(self):
        """Forget the cache, so the next prompt is read in full."""
        with self.lock:
            self.kv.clear()
            self.exact = 0

    @property
    def kv_tokens(self):
        return len(self.kv)


def _smoke_test():
    """python -m advisor.llm_engine --pte llama3_2.pte --tokenizer tokenizer.model [--verify] [--server-bin advisor_server]
    Loads the model, reads the fixed prefix, explains one sample alert twice
    (prefix reused, then an exact repeat) and prints the timings. --verify also
    re-reads everything from an empty cache and checks that the answer and every
    logit behind it are bit-identical (CRC-32 of the logits)."""
    import argparse
    from .findings import Finding
    from .playbooks import get_playbook, load_playbooks
    from .prompt import build_prompt, max_new_tokens, static_prefix
    from .validator import check_explanation

    ap = argparse.ArgumentParser()
    ap.add_argument("--pte", required=True)
    ap.add_argument("--tokenizer", required=True)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--lang", default="en", choices=["en", "hi"])
    ap.add_argument("--verify", action="store_true",
                    help="also re-run with an empty KV cache and check the answer is bit-identical")
    ap.add_argument("--server-bin", help="path to advisor_server (the native C++ engine; needed on a Pi 4)")
    ap.add_argument("--prefill-chunk", type=int, default=32,
                    help="prompt piece size; 0 = fewest calls (answers may then depend on the cache)")
    a = ap.parse_args()

    if a.server_bin:
        from .llm_native import NativeLlamaEngine
        engine = NativeLlamaEngine(a.server_bin, a.pte, a.tokenizer, threads=a.threads,
                                   prefill_chunk=a.prefill_chunk)
        kind = "native advisor_server"
    else:
        engine = LlamaEngine(a.pte, a.tokenizer, threads=a.threads, prefill_chunk=a.prefill_chunk)
        kind = "ExecuTorch Python runtime"
    print(f"[{kind}] loaded in {engine.load_s:.1f} s | {engine.threads} threads | context {engine.max_context_len} "
          f"| prompt pieces of {engine.prefill_chunk or 'up to ' + str(engine.max_tokens_per_call)} tokens")
    m = engine.prefill(static_prefix(a.lang))
    print(f"fixed prefix: {m['prefill_tokens']} tokens in {m['prefill_s']:.1f} s ({m.get('prefill_tok_s', 0):.1f} tok/s)")

    finding = Finding(source="sms", verdict="dangerous", score=0.97, category="bank_kyc_scam",
                      reasons=["sent from a 10-digit mobile number, but real banks send SMS from registered sender IDs",
                               "claims to be from a bank, but the link is not on an official .bank.in website",
                               "rushes you with a deadline or a threat to block or cut off a service"],
                      entities={"claims_to_be": "SBI", "claims_kind": "bank"}, language=a.lang)
    prompt = build_prompt(finding, get_playbook(load_playbooks(), finding.category))
    for label in ("alert", "same alert again"):
        text, m = engine.generate(prompt, max_new_tokens=max_new_tokens(a.lang))
        c = check_explanation(text, finding.verdict, a.lang)
        print(f"\n[{label}] read {m['prefill_tokens']} new tokens (reused {m['reused_tokens']}), "
              f"first token after {m['ttft_s']:.1f} s, {m['generated_tokens']} tokens at "
              f"{m.get('decode_tok_s', 0):.2f} tok/s, total {m['total_s']:.1f} s")
        print(f"Llama : {text}")
        print(f"valid : {c.ok} {c.flags if c.flags else ''}")
        last, last_m = text, m

    if a.verify:
        engine.reset()                          # forget the cache: read the whole prompt again
        text, m = engine.generate(prompt, max_new_tokens=max_new_tokens(a.lang))
        same_text = text == last
        same_logits = m.get("logits_crc32") == last_m.get("logits_crc32")
        print(f"\n[fresh, empty cache] read {m['prefill_tokens']} tokens in {m['prefill_s']:.1f} s; "
              f"same answer: {'yes' if same_text else 'NO'}; "
              f"same logits (CRC-32 {m.get('logits_crc32')}): {'yes' if same_logits else 'NO'}")
        if not same_text:
            old, new = last.split(), text.split()
            k = next((i for i, (x, y) in enumerate(zip(old, new)) if x != y), min(len(old), len(new)))
            print(f"first difference at word {k + 1}")
            print(f"fresh : {text}")
        if not (same_text and same_logits) and engine.prefill_chunk == 0:
            print("(expected with --prefill-chunk 0: how a prompt is split into calls changes the rounding)")


if __name__ == "__main__":
    _smoke_test()

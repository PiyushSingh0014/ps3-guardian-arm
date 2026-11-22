"""LLM backends for the advisor.

TemplateBackend     - no LLM; develop the whole pipeline on a laptop.
LlamaServiceBackend - talks to advisor/llm_service.py, which keeps Llama 3.2
                      loaded on the Pi and reuses the KV cache of the fixed
                      prompt prefix. The fast path (~15-20 s per new alert,
                      instant for repeats).
LlamaMainBackend    - runs ExecuTorch's `llama_main` once per alert. No extra
                      Python packages needed, but reloads the model every
                      time (~40-60 s per alert on a Pi 4). Kept as a fallback.

Every call returns timing numbers (time to first token, prefill and decode
tokens/s), so performance data for the report is logged for free.
"""
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

ASSISTANT_HEADER = "<|start_header_id|>assistant<|end_header_id|>"
_ETLOG_RE = re.compile(r"^[IDWEF] \d{2}:\d{2}:\d{2}\.\d+ executorch:")


@dataclass
class GenResult:
    text: str = ""
    metrics: dict = field(default_factory=dict)
    error: str = ""


class TemplateBackend:
    name = "template"

    def generate(self, prompt, max_new_tokens=None):
        return GenResult(error="template backend (no LLM)")


class LlamaServiceBackend:
    name = "llama_service"

    def __init__(self, url="http://127.0.0.1:8765", timeout_s=180, client=None):
        self.url, self.timeout_s = url.rstrip("/"), timeout_s
        self._client = client            # tests pass a FastAPI TestClient here

    def _http(self):
        if self._client is None:
            import httpx
            self._client = httpx.Client(base_url=self.url, timeout=self.timeout_s)
        return self._client

    def generate(self, prompt, max_new_tokens=None):
        payload = {"prompt": prompt}
        if max_new_tokens:
            payload["max_new_tokens"] = int(max_new_tokens)
        t0 = time.time()
        try:
            r = self._http().post("/generate", json=payload)
        except Exception as e:           # connection refused, timeout, ...
            return GenResult(error=f"Llama service not reachable at {self.url}: {type(e).__name__}")
        if r.status_code != 200:
            return GenResult(error=f"Llama service error {r.status_code}: {r.text[:200]}")
        d = r.json()
        metrics = dict(d.get("metrics") or {})
        metrics["wall_s"] = round(time.time() - t0, 3)
        return GenResult(text=d.get("text", ""), metrics=metrics)

    def health(self):
        try:
            r = self._http().get("/health")
            return r.json() if r.status_code == 200 else {"ok": False, "status": r.status_code}
        except Exception as e:
            return {"ok": False, "error": type(e).__name__}


def _metrics(s):
    def secs(a, b):
        if s.get(a) is not None and s.get(b) is not None:
            return (s[b] - s[a]) / 1000.0
        return None

    m = {"prompt_tokens": s.get("prompt_tokens"), "generated_tokens": s.get("generated_tokens"),
         "model_load_s": secs("model_load_start_ms", "model_load_end_ms"),
         "ttft_s": secs("inference_start_ms", "first_token_ms")}
    prefill = secs("inference_start_ms", "prompt_eval_end_ms")
    decode = secs("first_token_ms", "inference_end_ms")
    if s.get("prefill_token_per_sec"):
        m["prefill_tok_s"] = s["prefill_token_per_sec"]
    elif prefill and m["prompt_tokens"]:
        m["prefill_tok_s"] = m["prompt_tokens"] / prefill
    if s.get("decode_token_per_sec"):
        m["decode_tok_s"] = s["decode_token_per_sec"]
    elif decode and m["generated_tokens"]:
        m["decode_tok_s"] = max(m["generated_tokens"] - 1, 1) / decode
    return {k: (round(v, 3) if isinstance(v, float) else v) for k, v in m.items() if v is not None}


def parse_llama_main_stdout(stdout):
    """Split llama_main stdout into (answer_text, metrics)."""
    metrics, kept = {}, []
    for line in stdout.splitlines():
        if line.startswith("PyTorchObserver"):
            try:
                metrics = _metrics(json.loads(line[len("PyTorchObserver"):].strip()))
            except ValueError:
                pass
            continue
        if _ETLOG_RE.match(line):
            continue
        kept.append(line)
    text = "\n".join(kept)
    if ASSISTANT_HEADER in text:          # runner echoed the prompt: keep only the answer
        text = text.rsplit(ASSISTANT_HEADER, 1)[1]
    for tok in ("<|eot_id|>", "<|end_of_text|>"):
        text = text.split(tok, 1)[0]
    return text.strip(), metrics


class LlamaMainBackend:
    name = "llama_main"
    n_examples = 1          # every prompt token is re-read on each call, so keep it short

    def __init__(self, cmd, model_path, tokenizer_path, threads=4, temperature=0.0,
                 max_new_tokens=64, timeout_s=180, extra_args=None):
        self.cmd = cmd if isinstance(cmd, list) else shlex.split(cmd)
        self.model_path, self.tokenizer_path = model_path, tokenizer_path
        self.threads, self.temperature = threads, temperature
        self.max_new_tokens, self.timeout_s = max_new_tokens, timeout_s
        self.extra_args = extra_args or []

    def generate(self, prompt, max_new_tokens=None):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(prompt)
            prompt_path = f.name
        args = self.cmd + [f"--model_path={self.model_path}",
                           f"--tokenizer_path={self.tokenizer_path}",
                           f"--prompt_file={prompt_path}",
                           f"--max_new_tokens={max_new_tokens or self.max_new_tokens}",
                           f"--temperature={self.temperature}",
                           f"--cpu_threads={self.threads}"] + self.extra_args
        t0 = time.time()
        try:
            p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return GenResult(error=f"llama_main timed out after {self.timeout_s}s")
        except FileNotFoundError as e:
            return GenResult(error=f"llama_main not found: {e}")
        finally:
            os.unlink(prompt_path)
        if p.returncode != 0:
            return GenResult(error=f"llama_main exited {p.returncode}: {p.stderr[-300:]}")
        text, metrics = parse_llama_main_stdout(p.stdout)
        metrics["wall_s"] = round(time.time() - t0, 3)
        return GenResult(text=text, metrics=metrics)


def backend_from_env():
    """ADVISOR_BACKEND = template (default) | service | llama_main."""
    kind = os.environ.get("ADVISOR_BACKEND", "template")
    if kind == "service":
        return LlamaServiceBackend(url=os.environ.get("LLAMA_SERVICE_URL", "http://127.0.0.1:8765"),
                                   timeout_s=int(os.environ.get("LLAMA_TIMEOUT_S", "180")))
    if kind == "llama_main":
        return LlamaMainBackend(
            cmd=os.environ.get("LLAMA_MAIN", "./llama_main"),
            model_path=os.environ.get("LLAMA_PTE", "llama3_2.pte"),
            tokenizer_path=os.environ.get("LLAMA_TOKENIZER", "tokenizer.model"),
            threads=int(os.environ.get("LLAMA_THREADS", "4")),
            temperature=float(os.environ.get("LLAMA_TEMPERATURE", "0")),
            max_new_tokens=int(os.environ.get("LLAMA_MAX_NEW_TOKENS", "64")),
            timeout_s=int(os.environ.get("LLAMA_TIMEOUT_S", "180")))
    return TemplateBackend()

"""LLM backends for the advisor.

TemplateBackend  - no LLM; develop the whole pipeline on a laptop.
LlamaMainBackend - runs ExecuTorch's `llama_main` (Llama 3.2 on the Pi's CPU).
                   Simple but reloads the model on every call; the week-5
                   upgrade is a persistent service around create_text_llm_runner().

Every call returns the runner's own timing numbers (time to first token,
prefill and decode tokens/s), so performance data for the report is logged
for free.
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

    def generate(self, prompt):
        return GenResult(error="template backend (no LLM)")


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

    def __init__(self, cmd, model_path, tokenizer_path, threads=3, temperature=0.0,
                 max_new_tokens=128, timeout_s=120, extra_args=None):
        self.cmd = cmd if isinstance(cmd, list) else shlex.split(cmd)
        self.model_path, self.tokenizer_path = model_path, tokenizer_path
        self.threads, self.temperature = threads, temperature
        self.max_new_tokens, self.timeout_s = max_new_tokens, timeout_s
        self.extra_args = extra_args or []

    def generate(self, prompt):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(prompt)
            prompt_path = f.name
        args = self.cmd + [f"--model_path={self.model_path}",
                           f"--tokenizer_path={self.tokenizer_path}",
                           f"--prompt_file={prompt_path}",
                           f"--max_new_tokens={self.max_new_tokens}",
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
    """ADVISOR_BACKEND=template (default) or llama_main (+ LLAMA_* settings)."""
    if os.environ.get("ADVISOR_BACKEND", "template") == "llama_main":
        return LlamaMainBackend(
            cmd=os.environ.get("LLAMA_MAIN", "./llama_main"),
            model_path=os.environ.get("LLAMA_PTE", "llama3_2.pte"),
            tokenizer_path=os.environ.get("LLAMA_TOKENIZER", "tokenizer.model"),
            threads=int(os.environ.get("LLAMA_THREADS", "3")),
            temperature=float(os.environ.get("LLAMA_TEMPERATURE", "0")),
            max_new_tokens=int(os.environ.get("LLAMA_MAX_NEW_TOKENS", "128")),
            timeout_s=int(os.environ.get("LLAMA_TIMEOUT_S", "120")))
    return TemplateBackend()

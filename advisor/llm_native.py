"""Drives deploy/advisor_server (C++) from Python. Same interface as LlamaEngine.

Use this on the Raspberry Pi 4. The ExecuTorch pip wheel's custom LLM ops
library is compiled for Armv8.2-A and stops with "Illegal instruction" on the
Pi 4's Cortex-A72 (Armv8.0-A). advisor_server is built from source with the
same toolchain and flags as llama_main, so it runs on the Pi 4, and it needs
no torch or executorch Python packages.

The server keeps the model and the KV cache; this class only sends prompts
over stdin and reads one JSON line back (protocol in advisor_server.cpp).
"""
import json
import os
import select
import signal
import subprocess
import threading
import time


class NativeServerError(RuntimeError):
    pass


def _describe_exit(code):
    if code is not None and code < 0:
        try:
            name = signal.Signals(-code).name
        except ValueError:
            name = f"signal {-code}"
        hint = " (the binary uses instructions this CPU lacks)" if name == "SIGILL" else ""
        return f"stopped by {name}{hint}"
    return f"exited with code {code}"


class NativeLlamaEngine:
    def __init__(self, server_bin, pte_path, tokenizer_path, threads=4, start_timeout_s=600,
                 request_timeout_s=600):
        env = dict(os.environ)
        if isinstance(server_bin, (list, tuple)):    # tests: a command prefix such as [python, fake.py]
            prefix = list(server_bin)
        else:
            server_bin = os.path.abspath(os.path.expanduser(server_bin))
            if not os.path.isfile(server_bin):
                raise FileNotFoundError(f"advisor_server not found at {server_bin}")
            here = os.path.dirname(server_bin)       # libllama_runner.so lives next to it
            env["LD_LIBRARY_PATH"] = here + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
            prefix = [server_bin]
        self.cmd = prefix + [f"--model_path={os.path.expanduser(pte_path)}",
                    f"--tokenizer_path={os.path.expanduser(tokenizer_path)}", f"--cpu_threads={int(threads)}"]
        self.request_timeout_s = request_timeout_s
        self.lock = threading.RLock()
        self.stats = {"requests": 0, "prompt_tokens": 0, "reused_tokens": 0}
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None, env=env, bufsize=0)
        ready = self._read_reply(start_timeout_s)
        if not ready.get("ok"):
            raise NativeServerError(f"advisor_server failed to start: {ready.get('error')}")
        self.load_s = round(time.perf_counter() - t0, 3)
        self.threads = ready.get("threads", threads)
        self.max_context_len = ready.get("max_context_len")
        self.max_tokens_per_call = ready.get("max_tokens_per_call")

    # -- protocol ----------------------------------------------------------------
    def _read_reply(self, timeout_s):
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout_s)
        if not ready:
            raise NativeServerError(f"advisor_server did not answer within {timeout_s} s")
        line = self.proc.stdout.readline()
        if not line:
            code = self.proc.wait(timeout=5)
            raise NativeServerError(f"advisor_server {_describe_exit(code)}")
        return json.loads(line.decode("utf-8", errors="replace"))

    def _write_all(self, data):
        view = memoryview(data)
        while view:
            n = self.proc.stdin.write(view)       # unbuffered pipe: may write part of it
            view = view[n:]

    def _call(self, cmd, prompt="", max_new_tokens=0):
        data = prompt.encode("utf-8")
        with self.lock:
            if self.proc.poll() is not None:
                raise NativeServerError(f"advisor_server {_describe_exit(self.proc.returncode)}")
            try:
                self._write_all(f"{cmd} {int(max_new_tokens)} {len(data)}\n".encode("ascii") + data)
            except BrokenPipeError:
                code = self.proc.wait(timeout=5)
                raise NativeServerError(f"advisor_server {_describe_exit(code)}")
            reply = self._read_reply(self.request_timeout_s)
        if not reply.get("ok"):
            raise ValueError(reply.get("error", "advisor_server error"))   # bad request: HTTP 400
        return reply

    # -- same interface as LlamaEngine ---------------------------------------------
    def generate(self, prompt, max_new_tokens=64):
        reply = self._call("GEN", prompt, max_new_tokens)
        m = reply.get("metrics", {})
        self.stats["requests"] += 1
        self.stats["prompt_tokens"] += m.get("prompt_tokens", 0)
        self.stats["reused_tokens"] += m.get("reused_tokens", 0)
        return reply.get("text", ""), m

    def prefill(self, prompt):
        return self._call("PREFILL", prompt).get("metrics", {})

    def is_resident(self, prompt):
        return bool(self._call("CHECK", prompt).get("resident"))

    def reset(self):
        self._call("RESET")

    @property
    def kv_tokens(self):
        return self._call("INFO").get("kv_tokens")

    def close(self):
        try:
            self._call("QUIT")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

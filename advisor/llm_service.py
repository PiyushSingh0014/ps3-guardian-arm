"""Persistent Llama service for the advisor. Run it on the Pi, from the repo root:

    python -m advisor.llm_service --pte ~/executorch-deployment/llama3_2.pte \
        --tokenizer ~/executorch-deployment/tokenizer.model --threads 4

It loads the model once, reads the fixed prompt prefix (system text + worked
examples) into the KV cache, and then serves the app on 127.0.0.1:8765:

    POST /generate  {"prompt": "...", "max_new_tokens": 64}  -> {"text", "metrics"}
    POST /prefill   {"prompt": "..."}                        -> {"metrics"}
    GET  /health

Two caches make repeat alerts fast:
  * KV cache (in the engine): tokens shared with the previous prompt are not
    read again. With the v3 prompt that is the whole fixed prefix.
  * Answer cache (here): greedy decoding is deterministic, so an answer is
    stored by exact prompt, in memory and in a JSON-lines file. An alert
    explained once is instant afterwards, even after a restart. Fill it before
    a demo with `python -m advisor.warm_cache`.
When idle, the service re-reads the default language's prefix if another
language replaced it, so the next alert in that language is fast again.

It listens on 127.0.0.1 only and has no authentication: the app is its only client.
"""
import argparse
import hashlib
import json
import os
import threading
import time
from collections import OrderedDict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "ps3-guardian", "llm_answers.jsonl")


class GenerateIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)
    max_new_tokens: int = Field(64, ge=0, le=512)
    use_cache: bool = True


class PrefillIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)


class AnswerCache:
    """Exact-prompt answer cache, persisted as JSON lines (append-only)."""

    def __init__(self, path=None, max_items=5000):
        self.path, self.max_items = path, max_items
        self.items = OrderedDict()
        self.lock = threading.Lock()
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        self.items[d["key"]] = d
                    except (ValueError, KeyError):
                        continue
            while len(self.items) > max_items:
                self.items.popitem(last=False)

    @staticmethod
    def key(model_id, prompt, max_new_tokens):
        return hashlib.sha256(f"{model_id}\n{max_new_tokens}\n{prompt}".encode("utf-8")).hexdigest()

    def get(self, key):
        with self.lock:
            return self.items.get(key)

    def put(self, key, text, metrics):
        entry = {"key": key, "text": text, "metrics": metrics, "created": int(time.time())}
        with self.lock:
            self.items[key] = entry
            while len(self.items) > self.max_items:
                self.items.popitem(last=False)
            if self.path:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def __len__(self):
        return len(self.items)


class IdleRewarmer(threading.Thread):
    """Re-reads the default prefix into the KV cache after other prompts replaced it."""

    def __init__(self, engine, prompt, idle_s=3.0):
        super().__init__(daemon=True)
        self.engine, self.prompt, self.idle_s = engine, prompt, idle_s
        self.ids = engine.encode(prompt)
        self.last_request = time.time()
        self.rewarms = 0

    def touch(self):
        self.last_request = time.time()

    def tick(self):
        """One check: re-read the prefix if idle and it is no longer in the KV cache."""
        from .llm_engine import common_prefix_len
        if time.time() - self.last_request < self.idle_s:
            return False
        if not self.engine.lock.acquire(blocking=False):     # a request is running
            return False
        try:
            if common_prefix_len(self.engine.kv, self.ids) < len(self.ids):
                self.engine.prefill(self.prompt)
                self.rewarms += 1
                return True
        except Exception as e:                               # never kill the service over this
            print(f"[llm] re-warm failed: {e}")
        finally:
            self.engine.lock.release()
        return False

    def run(self):
        while True:
            time.sleep(1.0)
            self.tick()


def model_id_for(pte_path):
    st = os.stat(pte_path)
    return f"{os.path.basename(pte_path)}:{st.st_size}:{int(st.st_mtime)}"


def create_app(engine, cache=None, model_id="model", rewarmer=None):
    app = FastAPI(title="PS3 Guardian - Llama service")
    started = time.time()

    @app.get("/health")
    def health():
        s = engine.stats
        return {"ok": True, "model": model_id, "threads": engine.threads, "load_s": engine.load_s,
                "kv_tokens": len(engine.kv), "max_context_len": engine.max_context_len,
                "answer_cache_items": len(cache) if cache is not None else None,
                "requests": s["requests"],
                "reused_token_share": round(s["reused_tokens"] / s["prompt_tokens"], 3) if s["prompt_tokens"] else None,
                "rewarms": rewarmer.rewarms if rewarmer else None,
                "uptime_s": round(time.time() - started, 1)}

    @app.post("/generate")
    def generate(req: GenerateIn):
        if rewarmer:
            rewarmer.touch()
        key = cache.key(model_id, req.prompt, req.max_new_tokens) if cache is not None else None
        if req.use_cache and key:
            hit = cache.get(key)
            if hit:
                return {"text": hit["text"], "metrics": {**hit["metrics"], "cached": True}}
        try:
            text, metrics = engine.generate(req.prompt, max_new_tokens=req.max_new_tokens)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        finally:
            if rewarmer:
                rewarmer.touch()
        if key:
            cache.put(key, text, metrics)
        return {"text": text, "metrics": {**metrics, "cached": False}}

    @app.post("/prefill")
    def prefill(req: PrefillIn):
        if rewarmer:
            rewarmer.touch()
        try:
            return {"metrics": engine.prefill(req.prompt)}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    return app


def main():
    ap = argparse.ArgumentParser(description="Persistent Llama service for the PS3 advisor")
    ap.add_argument("--pte", default=os.environ.get("LLAMA_PTE", "llama3_2.pte"))
    ap.add_argument("--tokenizer", default=os.environ.get("LLAMA_TOKENIZER", "tokenizer.model"))
    ap.add_argument("--threads", type=int, default=int(os.environ.get("LLAMA_THREADS", "4")))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--warm", default="en", help="languages whose prefix to read at start-up, e.g. en or en,hi; "
                                                 "the first one is kept warm when idle")
    ap.add_argument("--cache-file", default=DEFAULT_CACHE)
    ap.add_argument("--no-answer-cache", action="store_true")
    a = ap.parse_args()

    from .llm_engine import LlamaEngine
    from .prompt import static_prefix

    print(f"[llm] loading {a.pte} with {a.threads} threads ...", flush=True)
    engine = LlamaEngine(a.pte, a.tokenizer, threads=a.threads)
    print(f"[llm] loaded in {engine.load_s:.1f} s; context {engine.max_context_len} tokens, "
          f"{engine.threads} threads", flush=True)

    langs = [x.strip() for x in a.warm.split(",") if x.strip()]
    for lang in reversed(langs):                 # the first language ends up resident
        m = engine.prefill(static_prefix(lang))
        print(f"[llm] read the '{lang}' prefix: {m['prefill_tokens']} tokens in {m['prefill_s']:.1f} s "
              f"({m.get('prefill_tok_s', 0):.1f} tok/s)", flush=True)

    cache = None if a.no_answer_cache else AnswerCache(a.cache_file)
    if cache is not None:
        print(f"[llm] answer cache: {len(cache)} entries in {a.cache_file}", flush=True)
    rewarmer = IdleRewarmer(engine, static_prefix(langs[0])) if langs else None
    if rewarmer:
        rewarmer.start()

    import uvicorn
    uvicorn.run(create_app(engine, cache, model_id_for(a.pte), rewarmer),
                host=a.host, port=a.port, workers=1, log_level="warning")


if __name__ == "__main__":
    main()

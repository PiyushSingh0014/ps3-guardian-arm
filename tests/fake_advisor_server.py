"""Stand-in for deploy/advisor_server (C++), speaking the same stdin/stdout protocol.

Uses the fake model from tests/fakes.py, so NativeLlamaEngine and the service can
be tested on a laptop. Environment switches:
  FAKE_SERVER_FAIL_START=1   report a start-up error, like a missing tokenizer
  FAKE_SERVER_CRASH_ON=GEN   die with SIGILL on that command, like the pip
                             wheel on a Raspberry Pi 4
"""
import json
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.fakes import make_engine  # noqa: E402

out = sys.stdout.buffer


def reply(obj):
    out.write(json.dumps(obj).encode("utf-8") + b"\n")
    out.flush()


threads = 4
for arg in sys.argv[1:]:
    if arg.startswith("--cpu_threads="):
        threads = int(arg.split("=", 1)[1])

if os.environ.get("FAKE_SERVER_FAIL_START"):
    reply({"ok": False, "event": "ready", "error": "could not load tokenizer tokenizer.model"})
    sys.exit(1)

engine = make_engine()
reply({"ok": True, "event": "ready", "load_s": 0.01, "threads": threads, "max_seq_len": 8,
       "max_context_len": engine.max_context_len, "max_tokens_per_call": engine.max_tokens_per_call,
       "kv_tokens": 0})

stdin = sys.stdin.buffer
while True:
    header = stdin.readline()
    if not header:
        break
    parts = header.decode("ascii").split()
    if not parts:
        continue
    cmd, max_new, nbytes = parts[0], int(parts[1]), int(parts[2])
    if cmd == "QUIT":
        reply({"ok": True})
        break
    prompt = stdin.read(nbytes).decode("utf-8")
    if os.environ.get("FAKE_SERVER_CRASH_ON") == cmd:
        os.kill(os.getpid(), signal.SIGILL)
    try:
        if cmd in ("GEN", "PREFILL"):
            text, metrics = engine.generate(prompt, max_new if cmd == "GEN" else 0)
            reply({"ok": True, "text": text, "metrics": {**metrics, "engine": "native"}})
        elif cmd == "CHECK":
            reply({"ok": True, "resident": engine.is_resident(prompt),
                   "prompt_tokens": len(engine.encode(prompt))})
        elif cmd == "RESET":
            engine.reset()
            reply({"ok": True})
        elif cmd == "INFO":
            reply({"ok": True, "kv_tokens": engine.kv_tokens, "threads": threads})
        else:
            reply({"ok": False, "error": f"unknown command {cmd}"})
    except ValueError as e:
        reply({"ok": False, "error": str(e)})

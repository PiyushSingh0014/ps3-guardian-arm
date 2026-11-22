"""The Pi's Llama files for the paired phones (update 44): GET /llama lists them, GET /llama/{name}
sends one.

Phone Guard runs the same Llama 3.2 1B model as the Pi when the phone is away from the Pi's Wi-Fi,
so that a scam alert gets its two-sentence explanation there too. The model is never in the repo
(licence and size): a phone copies it once from its own Pi, over the pinned HTTPS connection and
with the pairing token, like every other request (app/server.py). Only these two names can be
asked for, and their paths come from the Pi's environment (scripts/run_pi.sh), never from the
request:

    LLAMA_PTE        the ExecuTorch program, e.g. ~/executorch-deployment/llama3_2.pte
    LLAMA_TOKENIZER  its tokenizer,          e.g. ~/executorch-deployment/tokenizer.model

The list gives each file's size and SHA-256, so the phone checks what it received (a download
that stopped and went on, or a model the Pi replaced since).
"""
import hashlib
import os
import threading

# The name the phone asks for -> the environment variable that holds the Pi's path for it.
FILES = {"llama3_2.pte": "LLAMA_PTE", "tokenizer.model": "LLAMA_TOKENIZER"}


def path_of(name):
    """The Pi's file for this name, or None (an unknown name, not set, or not there)."""
    env = FILES.get(name)
    path = os.environ.get(env, "") if env else ""
    return path if path and os.path.isfile(path) else None


class Hashes:
    """SHA-256 of each file, worked out once (a 1 GB model takes a few seconds on a Pi 4) and again
    only when the file's size or time changes."""

    def __init__(self):
        self.known, self.lock = {}, threading.Lock()

    def of(self, path):
        st = os.stat(path)
        key = (os.path.realpath(path), st.st_size, st.st_mtime_ns)
        with self.lock:
            if key in self.known:
                return self.known[key]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        with self.lock:
            self.known[key] = h.hexdigest()
        return self.known[key]


def listing(hashes):
    """GET /llama: both files with their sizes and SHA-256, or None if either is missing."""
    files = []
    for name in FILES:
        path = path_of(name)
        if path is None:
            return None
        files.append({"name": name, "bytes": os.path.getsize(path), "sha256": hashes.of(path)})
    return {"model": "Llama 3.2 1B Instruct (ExecuTorch)", "files": files,
            "bytes": sum(f["bytes"] for f in files)}

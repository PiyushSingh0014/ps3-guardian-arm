# PS3 — Step 2: the first vertical slice

**SMS → detector → Finding → Llama advisor → validator → API + phone page.**
One thin path through the whole architecture, working end to end.

Why this comes right after step 1:

1. It puts the mandatory Llama + ExecuTorch requirement *inside the product*,
   not just in a terminal demo.
2. It fixes the `Finding` contract that every later detector (URL, network,
   DNS) will emit, so the advisor never has to change again.
3. It gives you something demoable by the end of week 2.

---

## Run it on your laptop (no Pi, no LLM needed)

```bash
pip install -r requirements.txt
pytest -q                                   # 11 tests, uses a fake llama_main
python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v"
uvicorn app.server:app --port 8000          # open http://localhost:8000
```

Without an LLM the advisor answers from its playbook templates (`source: template`).

## Run it on the Pi with Llama

You need the three files from step 1 (Track B): `llama_main`, `llama3_2.pte`,
`tokenizer.model`.

```bash
export ADVISOR_BACKEND=llama_main
export LLAMA_MAIN=$HOME/llama/llama_main
export LLAMA_PTE=$HOME/llama/llama3_2.pte
export LLAMA_TOKENIZER=$HOME/llama/tokenizer.model
export LLAMA_THREADS=3
export LD_LIBRARY_PATH=$HOME/llama          # only if you copied shared libs next to llama_main

python -m advisor.cli "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc.example/verify" --show-prompt
uvicorn app.server:app --host 0.0.0.0 --port 8000
```

Then open `http://<pi-ip>:8000` on a phone connected to the Pi's hotspot.

What to expect:

- The SpinQuant export config already sets a 2048-token context. The advisor
  prompt is about 300 tokens and the answer is capped at 128.
- Roughly 5 s before the first token (prefill) plus about 10 s for the answer
  on a Pi 5. This version also reloads the model on every request, which adds
  load time. The week-5 upgrade is a persistent runner service with streaming.
- Every call records prompt and generated tokens, time to first token, and
  prefill/decode tokens/s. Collect them; they are your report's performance data.
- If Llama ignores the answer format, set `INCLUDE_BOS_TOKEN = False` in
  `advisor/prompt.py` and pass `--num_bos=1` through `extra_args`.

---

## What each file does

| File | Role |
| --- | --- |
| `detectors/sms/detector.py` | Wraps the day-1 model; returns a `Finding` |
| `advisor/findings.py` | The `Finding` contract and verdict thresholds |
| `advisor/categorize.py` | Picks a playbook for a flagged message (keyword stopgap) |
| `advisor/playbooks/*.md` | Remediation steps, one file per scam type |
| `advisor/prompt.py` | Llama 3.2 chat prompt; sanitises the untrusted message |
| `advisor/backends.py` | `TemplateBackend`, `LlamaMainBackend`; parses runner metrics |
| `advisor/validator.py` | Checks every LLM answer before a user sees it |
| `advisor/advise.py` | Template first, then Llama, then validation |
| `app/server.py` | FastAPI `/check` endpoint + the phone-friendly page |
| `tests/` | Test suite + `fake_llama_main.py` for testing without a Pi |

## The contract every detector follows

```python
Finding(source="sms" | "url" | "flow" | "dns",
        verdict="safe" | "suspicious" | "dangerous",
        score=0.0-1.0, category="<playbook key>",
        reasons=[...human-readable evidence...],
        entities={...}, raw_text=<untrusted or None>, language="en" | "hi")
```

Build the URL, network and DNS detectors to return exactly this, and they plug
into the advisor and fusion engine with no changes.

## Safety design (put this in your report)

- **The detectors own the verdict.** An answer that calls a flagged message
  safe is rejected and the template is used instead.
- **Untrusted text is sanitised** before it reaches Llama: chat-template tokens
  stripped, the `<untrusted>` fence cannot be closed early, links defanged,
  length capped at 300 characters.
- **Output allowlist.** Only 1930, cybercrime.gov.in and sancharsaathi.gov.in
  survive. Any field where the model tried to write another number or link is
  dropped entirely and replaced with playbook text.
- **Steps are always verbatim from playbooks**, and the "call 1930" step is
  always included.
- **The API never echoes the raw message**, and the page renders everything as
  plain text, so no link in it is ever clickable.

## Known limitations (fix as you go)

- `categorize.py` is keyword-based. Replace it with your model's scam-type output.
- The contradiction check knows English plus a few Hindi phrases only.
- One model load per request (fixed by the persistent service in week 5).
- No authentication yet. Keep it on the lab network until the pairing token lands.

---

## What comes after this

1. **Make the SMS detector real** (text/LLM person). Train on UCI + Mishra-Soni +
   your consented Indian/Hinglish set; go 3-class (ham / spam / smishing) and add
   a scam-type output that replaces `categorize.py`. Then fine-tune a small
   multilingual encoder, export it to ExecuTorch as INT8, and compare it with the
   baseline on a real-only test set.
2. **Network capture** (network person). Pi as Wi-Fi hotspot, NFStream on live
   traffic; re-extract CIC-IDS2017 and UNSW-NB15 PCAPs with NFStream; LightGBM
   baseline; record a week of benign home/lab traffic.
3. **URL detector** (text/LLM person). Lexical LightGBM on PhiUSIIL + fresh
   OpenPhish URLs, plus a local threat-intel table. Returns `Finding(source="url")`.
   Links found in SMS get checked by it automatically.
4. **Network IDS + malware behaviour** (network person). LightGBM + benign-only
   autoencoder; DGA, DNS-tunnelling and beacon-periodicity detectors. Findings
   with `source="flow"` / `"dns"`.
5. **Fusion + response** (app person). Group Findings per device and sender,
   de-duplicate, apply nftables / dnsmasq actions for dangerous ones.
6. **Android companion + persistent Llama service with streaming.**
7. **Feature freeze at the end of week 6**, then Hailo, optional LoRA,
   evaluation, demo video and report.

## Adding playbooks

Copy any file in `advisor/playbooks/`, keep the format (`# Title`,
`severity:`, `summary:`, `## Steps` with a numbered list), and name it after
the category key it serves. Aim for about 25 by week 4. Hindi versions of the
step text are the next improvement for non-English users.

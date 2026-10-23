# PS3 Guardian, step 3: the fast Llama advisor

**SMS → detector → evidence → instant playbook answer → Llama 3.2 explanation (on the Pi, via ExecuTorch) → validator → phone page.**

Step 2 proved the path end to end. Step 3 makes the Llama part usable on a Raspberry Pi 4:

| | Step 2 | Step 3 |
| --- | --- | --- |
| What Llama writes | WHAT/WHY/STEPS format | exactly 2 sentences; the code picks the steps |
| What Llama sees | the (sanitised) message + rules | evidence only: scam type, one checked fact, warning signs, who it pretends to be |
| Prompt style | instructions ("never call it safe") | 3 worked examples, positive wording |
| Model process | `llama_main` per alert (reload ~12 s) | persistent service, model loaded once |
| Prompt reading | whole prompt every time | fixed prefix read once and reused from the KV cache |
| Repeat alerts | same cost again | instant (saved answers) |
| User sees | nothing until Llama finishes | playbook answer at once, Llama's explanation swapped in after checks |
| Time per new alert (Pi 4, estimate) | ~42 s measured | ~20 s |

---

## How it fits together

```
message ─► SmsDetector ─► Finding (verdict, category, reasons, claims_to_be)
                               │
                               ├─► Advisor.quick()   playbook template, instant ──► page shows it
                               │
                               └─► Advisor.explain() (background job)
                                      prompt v3 = [fixed prefix: system + 3 examples] + [this alert's evidence]
                                      └─► llm_service (Pi) ─► LlamaEngine: reuse KV for the shared prefix,
                                                               read only the new tokens, greedy decode
                                      ◄── 2 sentences ─► validator ─► page swaps them in
```

Files that changed or are new in step 3:

| File | Role |
| --- | --- |
| `advisor/prompt.py` | Prompt v3: evidence only, 3 worked examples (English and Hindi), fixed prefix |
| `advisor/validator.py` | Checks the 2 sentences: verdict contradiction, language, numbers/links, hedging, KYC wording |
| `advisor/advise.py` | `quick()` (template, instant) and `explain()` (Llama, validated); code picks the steps |
| `advisor/llm_engine.py` | Llama on the ExecuTorch Python runtime with KV-cache prefix reuse; `python -m advisor.llm_engine` is a smoke test |
| `advisor/llm_service.py` | Persistent service on 127.0.0.1:8765, answer cache, idle re-warm of the prefix |
| `advisor/warm_cache.py` | Pre-explains a CSV of messages; writes a review/benchmark table |
| `advisor/backends.py` | New `LlamaServiceBackend`; `llama_main` kept as a fallback |
| `app/server.py` | `/check` answers at once and starts a job; `/explain/{id}` returns the checked explanation |
| `detectors/sms/brands.py` | Who a message claims to be (SBI, India Post, ...) from a fixed list |
| `detectors/sms/rules_india.py` | Clearer warning-sign wording, most important first (model features unchanged) |
| `advisor/playbooks/*.md` | New `pretends:` and `fact:` lines that only Llama sees |
| `scripts/run_pi.sh` | Starts the service, waits for it, starts the app |

---

## Run on your laptop (no Pi, no LLM)

```bash
pip install -r requirements.txt
pytest -q
python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v" --sender 9812345678
uvicorn app.server:app --port 8000
```

`pytest` runs 38 tests. The engine and service tests use a fake model, so no torch is needed.

---

## Set up the Pi (once)

Clone the repo on the Pi (run `gh auth login` once; it shows a code to enter at github.com/login/device on your laptop):

```bash
sudo apt install -y git gh python3-venv
git config --global user.name "Arrehinus"
git config --global user.email "singhpiyush8414@gmail.com"
gh auth login
gh repo clone ps3-guardian ~/ps3-guardian
cd ~/ps3-guardian
git checkout step3
```

If `~/ps3-guardian` already exists (for example from a zip), rename it first with `mv ~/ps3-guardian ~/ps3-guardian-old`.

Then create the Python environment:

```bash
python3 -m venv ~/ps3-venv
source ~/ps3-venv/bin/activate
pip install --upgrade pip
pip install -r ~/ps3-guardian/requirements.txt
pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu
pip install -r ~/ps3-guardian/requirements-llm.txt
```

The torch line must use the CPU index: the normal ARM build from PyPI pulls several GB of CUDA libraries. If pip finds no 2.14.0, run `pip show torch` in the Windows `et-venv` you exported with and install that version instead.

Train the SMS model on the Pi (scikit-learn versions must match, so do not copy the .joblib). From WSL, copy `merged_sms.csv` over with `scp merged_sms.csv arrehinus@10.140.209.76:~` (the data is not in git). Then on the Pi:

```bash
cd ~/ps3-guardian
python detectors/sms/train_baseline.py --data ~/merged_sms.csv
```

---

## Run on the Pi

**1. Smoke test.** This loads the model, reads the fixed prefix, and explains one sample alert twice:

```bash
cd ~/ps3-guardian
source ~/ps3-venv/bin/activate
python -m advisor.llm_engine --pte ~/executorch-deployment/llama3_2.pte --tokenizer ~/executorch-deployment/tokenizer.model
```

You should see the load time, the prefix size and speed, then two explanations with timings. The second run reads only 1 new token.

Add `--verify` to also re-read everything from an empty cache and confirm the answer is identical. This takes about a minute longer, and the result is good evidence for the report that prefix reuse changes nothing but speed.

**2. Start everything:**

```bash
bash scripts/run_pi.sh
```

Then open the address it prints (`http://<the Pi's IP>:8000`) on a phone on the same hotspot. The service keeps running after you stop the app with Ctrl+C. To stop the service too, run `pkill -f advisor.llm_service`.

**3. Before a demo, pre-explain your test messages.** Run this in a second SSH session while the service is running:

```bash
cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
python -m advisor.warm_cache detectors/sms/sample_messages.csv
```

The answers are saved in `~/.cache/ps3-guardian/llm_answers.jsonl`. Those alerts are then instant, even after a reboot.

**4. Benchmark for the report** (fresh generations, no saved answers):

```bash
python -m advisor.warm_cache detectors/sms/sample_messages.csv --fresh --limit 6 --report eval/advisor_pi4.md
```

`eval/advisor_pi4.md` gives one table row per distinct prompt:

- prompt tokens, and how many were reused
- time to first token, decode speed and total time
- whether the validator accepted the answer, and the answer itself

Review every answer by hand. Because the prompts contain only evidence, a test set produces only a few dozen distinct prompts.

**5. Save the results to GitHub** (on the Pi):

```bash
cd ~/ps3-guardian
git add eval/advisor_pi4.md
git commit -m "Step 3: advisor timings on the Pi 4"
git push
```

When everything works on the Pi, merge the branch into `main`. On the laptop (WSL):

```bash
cd ~/ps3-guardian
git checkout step3
git pull
git checkout main
git merge step3
git push
```

Useful settings:

- `--threads 4` on the service: 4 threads gave the best prefill on the Pi 4, and decode is memory-bound at any thread count.
- `--warm en,hi`: also read the Hindi prefix at start-up. Only one prefix fits in the KV cache at a time. The first language is re-read when the service is idle.

---

## Speed on a Raspberry Pi 4 (estimates; replace with your measured table)

These estimates come from the Track B measurements in [eval/results_pi4.md](../eval/results_pi4.md): prefill about 13–15 tokens/s, decode about 4.4 tokens/s, model load about 12 s.

| Case | Llama reads | Llama writes | Time |
| --- | --- | --- | --- |
| Service start-up (once per boot) | ~600-token fixed prefix | none | ~1.5 min |
| New alert | ~140 tokens (this alert only) | ~40 tokens | ~20 s |
| Same scam type as the previous alert | ~80 tokens | ~40 tokens | ~15 s |
| Alert explained before | none | none | instant |
| Fallback `ADVISOR_BACKEND=llama_main` | whole ~350-token prompt, plus a 12 s model load | ~40 tokens | ~45 s |

Hindi answers need about 3 times more tokens, so expect about 35 s for a new Hindi alert.

---

## Safety design (put this in your report)

- **The detectors own the verdict.** An explanation that calls a flagged message safe is rejected, and the playbook text is shown instead.
- **Llama never sees text a scammer wrote.** The prompt contains only:
  - the scam type and one checked fact from the playbook
  - the warning signs the detector found
  - who the message claims to be, picked from a fixed list

  This removes prompt injection by construction, not just by filtering. Raw values such as the sender number, links and domain names are shown to the user by the UI and never pass through the model.
- **Belt and braces.** Every field is still stripped of chat-template tokens (`<|...|>`) before it enters the prompt, in case a future detector puts odd text in its reasons.
- **Output allowlist.** Only 1930, cybercrime.gov.in, sancharsaathi.gov.in and the `.bank.in` suffix may appear in Llama's text. A sentence that contains any other number or link is dropped whole.
- **Steps are code, not Llama.** They are verbatim from the reviewed playbooks, and the 1930 step is always included.
- **Llama tokens are never streamed to the user.** The page shows the playbook answer at once and swaps in Llama's text only after the validator accepts it.
- **Deterministic and reviewable.** Greedy decoding plus evidence-only prompts means a test set produces a small, fixed set of answers. `warm_cache.py` writes them all to one table for human review.
- **The API never echoes the raw message.** The page renders everything as plain text. The Llama service listens on 127.0.0.1 only.

---

## How the engine was verified

Besides the 38 unit tests, `advisor/llm_engine.py` was run on the real ExecuTorch 1.5.1 runtime with torch 2.14. The model was a tiny random Llama, exported with `export_llm` using the same settings as your model:

- 8da4w XNNPACK linears
- 8-bit embeddings
- `sdpa_with_kv_cache`
- a KV cache with dynamic shapes

The results:

- With the prefix reused from the KV cache, the answers were token-for-token identical to a fresh run on a new engine.
- The answers were also identical to ExecuTorch's own C++ text runner, the code `llama_main` uses, called through its Python binding.
- **Found along the way:** the C++ runner splits long prompts into chunks of `max_seq_len` tokens, one more than the exported limit (`max_seq_len - 1`). It fails on prompts longer than that limit. Our engine reads the limit from the program. With your 2048-token export this never triggers, but it is a good detail for the report.

---

## Known limitations / next

- Only one language prefix stays in the KV cache. Switching languages costs one prefix read (~45-60 s), after which the idle re-warm restores the default.
- `categorize.py` and `brands.py` are keyword-based. Replace them with your model's scam-type output, keeping the playbook keys.
- Playbook steps are English only. Hindi step text is the next content task.
- There is no authentication yet. Keep the app on the lab network until the pairing token lands.
- Next: URL detector, network flow IDS (NFStream + LightGBM), fusion, Android companion. They all emit the same `Finding`, so the advisor does not change.

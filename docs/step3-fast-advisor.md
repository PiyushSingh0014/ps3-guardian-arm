# PS3 Guardian, step 3: the fast Llama advisor

**SMS → detector → evidence → instant playbook answer → Llama 3.2 explanation (on the Pi, via ExecuTorch) → validator → phone page.**

Step 2 proved the path end to end. Step 3 makes the Llama part usable on a Raspberry Pi 4:

| | Step 2 | Step 3 |
| --- | --- | --- |
| What Llama writes | WHAT/WHY/STEPS format | exactly 2 sentences; the code picks the steps |
| What Llama sees | the (sanitised) message + rules | evidence only: scam type, one checked fact, warning signs, who it pretends to be |
| Prompt style | instructions ("never call it safe") | 3 worked examples, positive wording |
| Model process | `llama_main` per alert (reload ~12 s) | persistent service with a native C++ engine (`advisor_server`), model loaded once |
| Prompt reading | whole prompt every time | fixed prefix read once and reused from the KV cache, in fixed 32-token pieces so an answer never depends on earlier alerts |
| Repeat alerts | same cost again | instant (saved answers) |
| User sees | nothing until Llama finishes | playbook answer at once, Llama's explanation swapped in after checks |
| Time per new alert (Pi 4) | ~42 s measured | 25 s measured |

---

## How it fits together

```
message ─► SmsDetector ─► Finding (verdict, category, reasons, claims_to_be)
                               │
                               ├─► Advisor.quick()   playbook template, instant ──► page shows it
                               │
                               └─► Advisor.explain() (background job)
                                      prompt v3 = [fixed prefix: system + 3 examples] + [this alert's evidence]
                                      └─► llm_service (Pi) ─► advisor_server (C++, ExecuTorch): reuse KV for the
                                                               shared prefix, read only the new tokens, greedy decode
                                      ◄── 2 sentences ─► validator ─► page swaps them in
```

Files that changed or are new in step 3:

| File | Role |
| --- | --- |
| `advisor/prompt.py` | Prompt v4: evidence only (including what the scammer wants), 3 worked examples (English and Hindi), fixed prefix |
| `advisor/validator.py` | Checks the 2 sentences: verdict contradiction, language, numbers/links, hedging, KYC wording |
| `advisor/advise.py` | `quick()` (template, instant) and `explain()` (Llama, validated); code picks the steps |
| `deploy/advisor_server/` | **Native engine for the Pi 4:** `advisor_server.cpp` (Llama on ExecuTorch with KV-cache prefix reuse) and `build_pi4.sh`, which builds it like `llama_main` |
| `advisor/llm_native.py` | Runs `advisor_server` and talks to it over stdin/stdout |
| `advisor/llm_engine.py` | The same engine on the ExecuTorch Python runtime (Pi 5, laptops); `python -m advisor.llm_engine` is the smoke test for both |
| `advisor/llm_service.py` | Persistent service on 127.0.0.1:8765, answer cache, idle re-warm of the prefix |
| `advisor/warm_cache.py` | Pre-explains a CSV of messages; writes a review/benchmark table |
| `advisor/backends.py` | New `LlamaServiceBackend`; `llama_main` kept as a fallback |
| `app/server.py` | `/check` answers at once and starts a job; `/explain/{id}` returns the checked explanation |
| `detectors/sms/brands.py` | Who a message claims to be (SBI, India Post, ...) from a fixed list |
| `detectors/sms/rules_india.py` | Clearer warning-sign wording, most important first (model features unchanged) |
| `advisor/playbooks/*.md` | New `pretends:` and `fact:` lines that only Llama sees |
| `scripts/run_pi.sh` | Starts the service (with `advisor_server` when present), waits for it, starts the app |
| `deploy/tools/check_arm_isa.py` | Lists instructions a Cortex-A72 cannot run in a binary; how the pip-wheel crash was found |

---

## Run on your laptop (no Pi, no LLM)

```bash
pip install -r requirements.txt
pytest -q
python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v" --sender 9812345678
uvicorn app.server:app --port 8000
```

`pytest` runs 46 tests. The engine, native-server and service tests use a fake model, so no torch is needed.

---

## Set up the Pi (once)

Clone the repo on the Pi (run `gh auth login` once; it shows a code to enter at github.com/login/device on your laptop):

```bash
sudo apt install -y git gh python3-venv
git config --global user.name "Arrehinus"
git config --global user.email "singhpiyush8414@gmail.com"
gh auth login
gh repo clone ps3-guardian-arm ~/ps3-guardian
cd ~/ps3-guardian
git checkout step3
```

If `~/ps3-guardian` already exists (for example from a zip), rename it first with `mv ~/ps3-guardian ~/ps3-guardian-old`.

Then create the Python environment. On a Pi 4 the app does **not** need torch or the executorch Python package: Llama runs in the native `advisor_server` (next section).

```bash
python3 -m venv ~/ps3-venv
source ~/ps3-venv/bin/activate
pip install --upgrade pip
pip install -r ~/ps3-guardian/requirements.txt
```

Train the SMS model on the Pi (scikit-learn versions must match, so do not copy the .joblib). From WSL, copy `merged_sms.csv` over with `scp merged_sms.csv arrehinus@10.140.209.76:~` (the data is not in git). Then on the Pi:

```bash
cd ~/ps3-guardian
python detectors/sms/train_baseline.py --data ~/merged_sms.csv
```

---

## Build advisor_server (WSL, once)

`advisor_server` is the native Llama engine: the same KV-cache prefix reuse as `advisor/llm_engine.py`, in C++, built in your WSL ExecuTorch tree with the same toolchain and flags as `llama_main`. The script copies one source file next to `llama_main`, adds one build target and builds only that target.

Run these in **WSL on the laptop** (prompt `lenovo@...`), not on the Pi: the Pi has no ExecuTorch source tree or cross compiler. Copy the source folder from the Pi, build, and send the binary back:

```bash
scp -r arrehinus@10.140.209.76:~/ps3-guardian/deploy/advisor_server ~/
bash ~/advisor_server/build_pi4.sh ~/executorch
scp ~/executorch/cmake-out/examples/models/llama/advisor_server arrehinus@10.140.209.76:~/executorch-deployment/
```

Use the path of the ExecuTorch folder where you ran `examples/raspberry_pi/setup.sh pi4` if it is not `~/executorch` (`find ~ -maxdepth 3 -name arm-toolchain-pi4.cmake` shows it).

If you keep an `advisor_server` somewhere else on the Pi (for example a prebuilt copy in its own folder, with its own `libllama_runner.so` beside it), pass its path with `--server-bin` in the smoke test and start the service with `LLAMA_SERVER_BIN=<path> bash scripts/run_pi.sh`.

---

## Run on the Pi

**1. Smoke test.** This loads the model, reads the fixed prefix, explains one sample alert twice, and with `--verify` re-reads everything from an empty cache to confirm that the answer, and every logit behind it, is bit-identical:

```bash
cd ~/ps3-guardian
source ~/ps3-venv/bin/activate
python -m advisor.llm_engine --server-bin ~/executorch-deployment/advisor_server --pte ~/executorch-deployment/llama3_2.pte --tokenizer ~/executorch-deployment/tokenizer.model --verify
```

You should see the load time, the prefix size and speed, then two explanations with timings. The second run reads only the last few tokens (up to 32). The last line should say `same answer: yes; same logits (CRC-32 ...): yes`. That is the evidence for the report that reusing the cache changes nothing but speed.

**2. Start everything** (it uses `~/executorch-deployment/advisor_server` automatically):

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
- `--prefill-chunk 32` (default; `LLAMA_PREFILL_CHUNK` for `run_pi.sh`): the prompt piece size. `0` uses the fewest forward calls, but then an answer can depend on which alert came before (see "How the engine was verified").

---

## Why a native server on the Pi 4 (put this in your report)

The first plan ran Llama through the ExecuTorch Python runtime (`pip install executorch`). On the Pi 4 it stopped with `Illegal instruction` while loading the model.

**What we found.** We disassembled every ARM64 library in the `executorch` 1.5.1 wheel with `deploy/tools/check_arm_isa.py`:

- `libcustom_ops_aot_lib.so` contains 43 Armv8.1 LSE atomic instructions (`CAS`, `LDADD`, ...) with no run-time CPU check, plus dot-product instructions.
- These sit in the code that registers the custom LLM ops (`llama::custom_sdpa`, `llama::update_cache`). The model needs those ops, so loading it hits the bad instructions.
- The cause is one line in ExecuTorch's `extension/llm/custom_ops/CMakeLists.txt`, which compiles the library with `-march=armv8.2-a+dotprod` for every aarch64 build.
- The Pi 4's Cortex-A72 only implements Armv8.0-A (its features are `fp asimd crc32`), so the first such instruction stops the program.
- The other wheel libraries use "outline atomics", which check the CPU at run time, so they are safe.

**Fix.** `advisor_server` is the same engine in C++, built from source with the Pi 4 toolchain and flags (`-march=armv8-a -mtune=cortex-a72`), exactly like `llama_main`. It runs the same kernels `llama_main` already runs on this Pi.

One catch: that CMake file also hands `-march=armv8.2-a+dotprod` to every program that links the custom ops, `llama_main` included, and it comes after the toolchain's `-march=armv8-a`, so it wins. In our first build the compiler used it to put two Armv8.1 atomics into `advisor_server.cpp` (in shared-pointer clean-up that the tests never reached). `build_pi4.sh` now compiles that file for `armv8-a` again. After the fix the scan finds no Armv8.1 atomics in our code. The newer instructions left are all in kernels that XNNPACK and KleidiAI pick at run time from the CPU's features, or in int8 attention kernels for a quantized KV cache, which this model does not use. The same is true of `llama_main`.

Side benefits:

- The Pi needs no PyTorch install (about 600 MB saved on disk, several hundred MB of RAM saved).
- The service starts faster, because there are no Python ML imports.

---

## Speed on a Raspberry Pi 4

Measured on 2026-10-24 (details in [eval/results_pi4.md](../eval/results_pi4.md)). The table is the first smoke-test run; the 32-token pieces changed it as noted below:

| Case | Llama reads | Llama writes | Time |
| --- | --- | --- | --- |
| Service start-up (once per boot) | model load, then the 480-token fixed prefix | none | 13.4 s + 32.0 s |
| New alert | 138 tokens (this alert only) | 53 tokens | **25.0 s** (first token after 9.3 s) |
| Same prompt again, from the KV cache | 1 token (up to 32 with the pieces) | 53 tokens | 16.0 s |
| Alert explained before (answer cache) | none | none | instant |
| Whole prompt from an empty cache | 618 tokens | 53 tokens | 40.6 s to read, then ~16 s |
| Fallback `ADVISOR_BACKEND=llama_main` | whole ~350-token prompt, plus a 12 s model load | ~40 tokens | ~45 s (estimate) |

- Reading runs at about 15 tokens/s; writing at 3.4 tokens/s.
- Writing is slower than Track B's 4.4 tokens/s because each new token also attends to the whole context, here 620–670 tokens. Track B's own numbers show the same trend (see results). A shorter fixed prefix would make every answer faster.
- With the 32-token pieces (measured): the prefix takes 35.5 s instead of 32.0 s, and a new alert's first token about 1 s later. Each extra forward call costs about 0.3 s, because a 32-token piece is too little work to hide re-reading the weights.
- Benchmark of 6 different alerts (`warm_cache --fresh`): 17.8–20.9 s each. When the previous alert was the same scam type, 512 tokens were reused and the first token came after 5.4–6.2 s.
- Hindi answers need about 3 times more tokens, so expect about 50 s for a new Hindi alert.

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
- **Deterministic and reviewable.** Greedy decoding plus evidence-only prompts means a test set produces a small, fixed set of answers. Prompts are read in fixed 32-token pieces, so an answer is bit-for-bit the same whichever alert came before (`--verify` checks a CRC-32 of the logits). The answers `warm_cache.py` writes to its review table are therefore exactly what users will see.
- **The API never echoes the raw message.** The page renders everything as plain text. The Llama service listens on 127.0.0.1 only.

---

## How the engine was verified

Besides the 50 unit tests, `advisor/llm_engine.py` was run on the real ExecuTorch 1.5.1 runtime with torch 2.14. The model was a tiny random Llama, exported with `export_llm` using the same settings as your model:

- 8da4w XNNPACK linears
- 8-bit embeddings
- `sdpa_with_kv_cache`
- a KV cache with dynamic shapes

The results:

- With the prefix reused from the KV cache, the answers were token-for-token identical to a fresh run on a new engine.
- The answers were also identical to ExecuTorch's own C++ text runner, the code `llama_main` uses, called through its Python binding.
- **Found along the way:** the C++ runner splits long prompts into chunks of `max_seq_len` tokens, one more than the exported limit (`max_seq_len - 1`). It fails on prompts longer than that limit. Our engine reads the limit from the program. With your 2048-token export this never triggers, but it is a good detail for the report.

`advisor_server` (the native engine) was built from ExecuTorch v1.5.1 with `build_pi4.sh` in two ways, natively and cross-compiled for the Pi 4. The results:

- **Native x86 build:** on the same tiny model and four advisor prompts, its answers, reused-token counts and read-token counts were identical to the Python-runtime engine. The `--verify` re-read from an empty cache was identical too.
- **Cross-compiled for the Pi 4** (`-march=armv8-a -mtune=cortex-a72`, KleidiAI on): run under QEMU emulating a Cortex-A72, it read the 1,636-token prefix in 511-token chunks, answered three alerts, and gave identical answers with and without prefix reuse.
  - No instruction trapped.
  - The same emulated CPU traps an Armv8.1 atomic instruction, which is exactly what crashes the pip wheel on the real Pi.
  - On one of three prompts, the Arm and x86 answers from the random-weight test model drift apart after about ten tokens. That is normal floating-point rounding between NEON and AVX kernels at a near tie; each build always agrees with itself.
  - After the `armv8-a` fix above, the rebuilt binary passed the same checks. It also passed the exact smoke-test command from "Run on the Pi" (4 threads, `--verify`) under the emulated Cortex-A72.

**On the real Pi 4 the reuse check failed at first (2026-10-24).** Re-reading the whole prompt from an empty cache gave a slightly different answer than the run that reused the cached prefix. Both answers were fine; the difference is rounding:

- How the attention kernel splits its matrix products follows the length of each forward call: its key/value blocks are `min(512, positions seen so far in this call)` wide. Most likely the cause is Eigen's matrix multiply: on Arm it assumes a 16 KB L1 cache and splits sums longer than about 200 terms, and where it splits depends on that width.
- Reading the prefix (480 tokens) in one call and the alert (138) in a second call therefore rounds the cached keys and values a little differently from reading all 618 tokens at once. At a near-tie, greedy decoding then picks another word.
- The tiny test model hid this, because its call boundaries happened not to change any sum, and x86 builds split less. A test model with the 1B's attention shape (head size 64, 2048 context) shows it under QEMU. With one call per prompt, the CRC-32 of the logits after a warm prefix differed from a fresh read in 3 of 4 cache histories.
- **Fix:** prompts are read in 32-token pieces at fixed positions (0, 32, 64, ...). The cache is reused only up to a piece boundary that earlier calls computed exactly. Every position is then computed by the same calls whatever was cached. Under QEMU the logits CRC was identical in all five histories: fresh, prefix warmed, after another KYC alert, after a parcel alert, and an exact repeat.
- The unit tests now use a fake model whose output depends on how the prompt was split, like the real kernel. One test shows that without the pieces a warm-up changes the answer; another checks six different histories with them.

---

## Known limitations / next

- Only one language prefix stays in the KV cache. Switching languages costs one prefix read (~45-60 s), after which the idle re-warm restores the default.
- `categorize.py` and `brands.py` are keyword-based. Replace them with your model's scam-type output, keeping the playbook keys.
- Playbook steps are English only. Hindi step text is the next content task.
- There is no authentication yet. Keep the app on the lab network until the pairing token lands.
- Next: URL detector, network flow IDS (NFStream + LightGBM), fusion, Android companion. They all emit the same `Finding`, so the advisor does not change.

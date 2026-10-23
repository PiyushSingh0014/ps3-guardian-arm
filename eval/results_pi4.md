# Llama 3.2 1B on the Raspberry Pi 4: baseline measurements (Track B)

Measured on 2026-10-23 with ExecuTorch's `llama_main` runner, greedy decoding. These are the reference numbers for every later Arm optimisation.

## Setup

| Item | Value |
| --- | --- |
| Board | Raspberry Pi 4 Model B Rev 1.5, 4 GB LPDDR4-3200 (3.7 GiB usable) |
| CPU | Broadcom BCM2711: 4× Arm Cortex-A72 at 1.8 GHz, Armv8.0-A with NEON. No dot-product or i8mm instructions, so KleidiAI's int8 kernels do not apply. |
| Storage | 128 GB USB 3.2 pendrive (boot and model) |
| OS | Raspberry Pi OS Lite 64-bit (Debian 13 "Trixie"), kernel 6.18.50 |
| Model | Llama 3.2 1B Instruct, Meta's SpinQuant INT4 checkpoint (`Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8`) |
| Export | ExecuTorch `release/1.5`: `export_llm` with `llama_xnnpack_spinquant.yaml` (details below) |
| Program size | ≈1.0 GB `.pte` |
| Runtime | `llama_main` from ExecuTorch `release/1.5`, XNNPACK delegate. Cross-compiled in WSL2 with `examples/raspberry_pi/setup.sh pi4` (Arm GNU toolchain 14.3.rel1, `-march=armv8-a -mtune=cortex-a72`). |

What the export does:

- 8-bit dynamic activations with 4-bit weights, group size 32
- 8-bit output layer and 8-bit embeddings
- a KV cache and the custom SDPA op
- maximum sequence and context length of 2048 tokens

## 1. Thread sweep

Short prompt (12 tokens), 63 generated tokens, same prompt for every run.

| Threads | Prefill (tok/s) | Decode (tok/s) | SoC temperature after run |
| --- | --- | --- | --- |
| 2 | 7.43 | 4.50 | 57.9 °C |
| 3 | 10.06 | 4.48 | 60.3 °C |
| 4 | **12.70** | 4.37 | 60.8 °C |

- **Model load:** about 11.7 s each time `llama_main` starts.
- **Thermals:** every run stayed below 61 °C, far from the Pi 4's 80 °C throttling point, so there was no throttling.

## 2. Chat-template tests (advisor prompts)

| Test | Prompt | Prompt tokens | Result |
| --- | --- | --- | --- |
| A | Llama 3.2 chat template with a rule-style system prompt (WHAT / WHY / STEPS format, "never call the message safe") | 123 | Template tokens parsed correctly and generation stopped at `<\|eot_id\|>`. But the 1B model refused instead of answering: it misread the negative rule. |
| B | [`deploy/prompts/advisor_test2.txt`](../deploy/prompts/advisor_test2.txt): one worked example, positive wording, "exactly 2 short sentences" | 222 | A usable explanation (below) |

Timings for test B:

| Stage | Time |
| --- | --- |
| Model load | 11.7 s |
| Prefill: 222 tokens at 15.68 tok/s (first token) | 14.2 s |
| Decode: 67 tokens at 4.02 tok/s | 16.7 s |
| **End to end** | **≈42.5 s** |

Llama's answer for test B, verbatim:

> This message is likely a scam because it asks you to update your Know Your Account (KYC) information, which is not something a legitimate bank would do. The link provided is not on the official .bank.in domain, and the urgent threat to block your account is a tactic used by scammers to create a sense of panic.

Problems in that answer, and the step-3 fix for each:

| Problem | Fix in step 3 (prompt v3 + validator v3) |
| --- | --- |
| "Know Your Account" | The prompt spells out "KYC (Know Your Customer)"; the validator corrects wrong expansions |
| Claims banks never ask for KYC (false) | A checked playbook fact: banks do ask, but only at a branch or in their official app or website |
| "likely a scam" although the scanner is confident | Assertive worked examples; the validator removes hedges for high-confidence verdicts |
| Ignored the 10-digit-sender clue | The sender clue is listed first among the warning signs |

## 3. What the numbers mean

**Decode is limited by memory bandwidth, not by compute.**

- Every new token reads almost all the weights: about 0.85 GB (4-bit linear layers with their scales, plus the 8-bit output layer).
- At about 4.4 tokens/s that is roughly 3.5–3.8 GB/s, close to what the Pi 4's 32-bit LPDDR4 delivers in practice (12.8 GB/s is the theoretical peak).
- More threads do not help, as the flat decode column shows.
- Only reading fewer bytes per token helps: a smaller model, a lower-bit output layer, or shorter answers.

**Prefill is limited by compute.**

- Prefill processes the whole prompt in large matrix multiplies, so it scales with cores: 1.71× from 2 to 4 threads.
- It also gets faster with longer prompts: test B reached 15.7 tok/s on 222 tokens, above any rate in the 12-token sweep.

**Starting the process is expensive.** Loading the model takes 11.7 s per run, a quarter of test B's time.

## 3b. Finding: the ExecuTorch pip wheel cannot run on the Pi 4

We tried to run Llama through the ExecuTorch Python runtime (`executorch` 1.5.1 wheel from PyPI, `torch` 2.14.0 CPU) for the persistent service. It stopped with `Illegal instruction` while loading the model.

**Cause.** We disassembled every ARM64 library in the wheel with `deploy/tools/check_arm_isa.py`:

- `libcustom_ops_aot_lib.so` holds the custom LLM ops (`llama::custom_sdpa`, `llama::update_cache`) that the exported model needs.
- It contains 43 Armv8.1 LSE atomic instructions with no run-time CPU check.
- The reason: ExecuTorch's `extension/llm/custom_ops/CMakeLists.txt` adds `-march=armv8.2-a+dotprod` to every aarch64 build.
- The Pi 4's Cortex-A72 implements Armv8.0-A only (`fp asimd crc32`), so it traps on the first such instruction.
- The wheel's other libraries check for LSE at run time (outline atomics) and are safe.

**Fix.** A native C++ engine, `advisor_server`, built from source with the Pi 4 toolchain and flags (`-march=armv8-a -mtune=cortex-a72`), like `llama_main`. It runs the same kernels as `llama_main`, needs no PyTorch on the Pi, and is what the step-3 service uses on this board.

The same CMake line also reaches every program that links the custom ops: their compile flags end with `-march=armv8.2-a+dotprod`. So `build_pi4.sh` compiles our own source file for `armv8-a` again; without that, the compiler had placed two Armv8.1 atomics in it. The newer instructions left in the binary are all in kernels that XNNPACK and KleidiAI choose at run time from the CPU's features, or in int8 attention kernels for a quantized KV cache, which this model does not use.

## 4. Design decisions taken from these numbers (step 3)

1. **Keep the model loaded:** a persistent Llama service removes the 11.7 s load from every alert.
2. **Read the fixed part of the prompt once:**
   - The system text and worked examples are the same for every alert.
   - They stay in the KV cache, so only about 140 new tokens are read per alert.
3. **Short answers:** exactly 2 sentences, about 40 tokens, because decode at about 4.4 tok/s dominates.
4. **Show the playbook answer instantly,** then swap in Llama's explanation once the validator accepts it.
5. **4 threads:** best prefill, with decode unchanged.
6. **Save answers for repeat alerts:** greedy decoding is deterministic, so a saved answer is exactly what Llama would write again.

Expected with step 3 on this Pi: about 20 s for a new alert and instant for a repeat, against about 42 s here. Measured: 25 s (section 5). The per-alert table will go in `eval/advisor_pi4.md`.

## 5. Step 3 on the Pi 4: first run of the native engine

Measured on 2026-10-24 with the smoke test (`python -m advisor.llm_engine --server-bin ... --verify`): `advisor_server` with 4 threads, the same `llama3_2.pte`, and a sample bank-KYC alert. This run read prompts in as few calls as possible (before the 32-token pieces below).

| Stage | Tokens | Time | Rate |
| --- | --- | --- | --- |
| Model load (once per boot) | | 13.4 s | |
| Fixed prefix (once per boot) | 480 read | 32.0 s | 15.0 tok/s |
| New alert: reading | 138 read, 480 reused | 9.3 s to the first token | 14.8 tok/s |
| New alert: writing | 53 written | 15.7 s | 3.37 tok/s |
| **New alert, end to end** | | **25.0 s** | |
| Same prompt again (KV cache only) | 1 read, 617 reused | 16.0 s | |
| Whole prompt from an empty cache | 618 read | 40.6 s to read | 15.2 tok/s |

Against Track B's 42.5 s for test B (section 2), a new alert is 1.7× faster. A repeat alert is instant from the answer cache.

**Writing slows down as the context grows.**

| Run | Context while writing | Writing speed |
| --- | --- | --- |
| Track B, 12-token prompt | ~13–75 tokens | 4.37 tok/s |
| Track B, test B | ~223–289 tokens | 4.02 tok/s |
| Step 3, sample alert | ~619–671 tokens | 3.37 tok/s |

- A straight line through the two Track B points predicts about 3.5 tok/s at step 3's context, close to the 3.37 measured. So the lower speed comes from the longer prompt, not from the new engine.
- Each token of context adds roughly 0.09 ms to every written token: the attention reads all cached keys and values.
- So a shorter fixed prefix (fewer or shorter worked examples) makes every answer faster.

**Finding: reusing the cache changed the answer's rounding.** The smoke test's last check re-read the whole prompt from an empty cache and got a slightly different answer (`identical: NO`). Both answers were reasonable. The cause:

- The attention kernel splits its matrix products by the length of each forward call.
- Most likely through Eigen's matrix multiply, which on Arm assumes a 16 KB L1 cache and so splits long sums.
- Reading the prefix and the alert in two calls therefore rounds differently from reading the whole prompt in one call.
- A test model with the same attention shape reproduces this under QEMU on an emulated Cortex-A72; x86 builds do not show it.

**Fix (step 3 update):** prompts are read in 32-token pieces at fixed positions, and the cache is reused only up to a piece boundary. An answer then depends only on its prompt. Under QEMU the CRC-32 of the logits was identical after five different cache histories. The cost is a few more forward calls per alert; re-measure with the smoke test.

**Wording found in the same run.** Llama wrote "...to trick you into updating your KYC, which is a legitimate process." The validator accepted it, but in a scam warning it reads as approval.

- The playbook fact that led to it ("Banks do ask customers to update KYC, but only...") is now "Banks update KYC only at a branch or through their official app or website...".
- The validator now rejects "is a legitimate / genuine / safe ..." for flagged messages. The template is shown instead.

## Reproduce

On the Pi:

```bash
cd ~/executorch-deployment
source setup_env.sh
bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh
bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh ~/ps3-guardian/deploy/prompts/advisor_test2.txt 4
```

The script also records RSS memory and throttling flags, which the first sweep did not capture. See [`deploy/README.md`](../deploy/README.md) for the export and build steps.

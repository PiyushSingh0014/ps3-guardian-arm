# Track B: Llama 3.2 1B on the Raspberry Pi 4 with ExecuTorch

How the model was exported, how `llama_main` was built for the Pi 4, and how it was measured. Results are in [`eval/results_pi4.md`](../eval/results_pi4.md).

The model files are **not in git**: the `.pte` is about 1 GB, over GitHub's 100 MB limit, and the Llama weights, plus anything exported from them, are covered by Meta's licence. Keep them on the laptop and the Pi only.

## What ends up on the Pi

Everything lives in `~/executorch-deployment`:

| File | From |
| --- | --- |
| `llama3_2.pte` | export, step 2 (≈1.0 GB) |
| `tokenizer.model` | the Hugging Face download, step 1 |
| `llama_main` | the cross-compile, step 3 |
| `libllama_runner.so` | the cross-compile, step 3 |
| `setup_env.sh` | sets `LD_LIBRARY_PATH` so `llama_main` finds `libllama_runner.so` |

## 1. Get the model (once)

On Hugging Face, accept the Llama 3.2 licence for `meta-llama/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8`. Download three files into `C:\Users\Lenovo\llama-spinquant`:

- `consolidated.00.pth`
- `params.json`
- `tokenizer.model`

## 2. Export the `.pte` (Windows laptop, PowerShell)

Activate the `et-venv` that has ExecuTorch `release/1.5` installed, then run:

```powershell
cd D:\ARM\ps3-starter\executorch
python -m extension.llm.export.export_llm `
  --config examples/models/llama/config/llama_xnnpack_spinquant.yaml `
  +base.model_class="llama3_2" `
  +base.checkpoint="C:/Users/Lenovo/llama-spinquant/consolidated.00.pth" `
  +base.params="C:/Users/Lenovo/llama-spinquant/params.json"
```

It ends with `Saved exported program to ./llama3_2.pte`.

What `llama_xnnpack_spinquant.yaml` sets:

- 8-bit dynamic activations with 4-bit weights, group size 32
- 8-bit output layer and 8-bit embeddings
- a KV cache with the custom SDPA op
- maximum sequence and context length of 2048 tokens
- end-of-sequence ids 128009 and 128001

## 3. Build `llama_main` for the Pi 4 (WSL2 Ubuntu)

In your WSL clone of ExecuTorch `release/1.5`:

```bash
cd ~/executorch
examples/raspberry_pi/setup.sh pi4
```

The script downloads the Arm GNU toolchain 14.3.rel1 and builds with `-march=armv8-a -mtune=cortex-a72`. Problems we hit, and their fixes:

| Symptom | Fix |
| --- | --- |
| `pybind11` cannot find `Python.h` | `sudo apt install -y python3-dev` |
| `Killed signal terminated program cc1plus` (out of memory) | Put `[wsl2]`, `processors=4` and `swap=16GB` in `C:\Users\Lenovo\.wslconfig`. Run `wsl --shutdown`, then `setup.sh pi4 --skip-env-setup`. |
| CMake 4 refuses old `cmake_minimum_required` | `export CMAKE_POLICY_VERSION_MINIMUM=3.5` (in `~/.bashrc`) |
| `Failed to connect to system scope bus` from apt | Harmless in WSL; ignore it |

To find the two files the build produced:

```bash
find ~/executorch -name llama_main -type f
find ~/executorch -name libllama_runner.so
```

## 4. Copy to the Pi (from WSL)

The Pi's address can change on the phone hotspot. Check it with `hostname -I` on the Pi, and edit the first line if needed:

```bash
PI=arrehinus@10.140.209.76
ssh $PI mkdir -p executorch-deployment
scp /mnt/d/ARM/ps3-starter/executorch/llama3_2.pte $PI:~/executorch-deployment/
scp /mnt/c/Users/Lenovo/llama-spinquant/tokenizer.model $PI:~/executorch-deployment/
```

Copy `llama_main` and `libllama_runner.so` the same way, using the paths `find` printed.

## 5. Run and measure (on the Pi)

```bash
cd ~/executorch-deployment
source setup_env.sh
./llama_main --model_path=llama3_2.pte --tokenizer_path=tokenizer.model \
  --prompt="Explain in one line why an SMS asking for your OTP is dangerous." \
  --max_new_tokens=64 --temperature=0 --cpu_threads=4
```

The last `PyTorchObserver {...}` line holds the timing numbers.

To measure properly, run the benchmark script:

```bash
bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh
```

It runs a thread sweep and prints a Markdown table with these columns:

- prefill and decode tokens/s
- load time and time to first token
- RSS memory
- temperature and throttle flags

To test a chat-template prompt file:

```bash
bash ~/ps3-guardian/deploy/pi/bench_llama_main.sh ~/ps3-guardian/deploy/prompts/advisor_test2.txt 4
```

## Prompt files

- `prompts/advisor_test2.txt`: the few-shot prompt that gave the first usable 2-sentence explanation (test B in the results).
- Test A (the rule-style prompt that made the model refuse) is `~/executorch-deployment/advisor_test.txt` on the Pi. Copy it here to keep the record complete.

## Licence

Built with Llama. Llama 3.2 is licensed under the Llama 3.2 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved. Use it in line with Meta's Acceptable Use Policy.

# PS3 Guardian

On-device threat, phishing and scam detection for the **Arm Bharat AI-SoC Student Challenge, PS3**.

Specialist detectors flag scam SMS, phishing links and suspicious network behaviour in milliseconds. **Llama 3.2 1B**, running on the Raspberry Pi 4's Arm CPU through **ExecuTorch**, explains each alert in plain English or Hindi, and the app shows what to do next. Nothing leaves the device.

## Status

| Part | State | Details |
| --- | --- | --- |
| Track A: SMS scam detector baseline | done | [eval/results_sms.md](eval/results_sms.md) |
| Step 2: advisor vertical slice (SMS → advisor → app) | done (laptop; template and `llama_main` backends) | [docs/step2-vertical-slice.md](docs/step2-vertical-slice.md) |
| Track B: Llama 3.2 1B on the Pi 4 via ExecuTorch | done: 12.7 tok/s prefill, 4.4 tok/s decode | [eval/results_pi4.md](eval/results_pi4.md), [deploy/README.md](deploy/README.md) |
| Step 3: fast advisor (persistent Llama service, prompt v3) | code ready on branch `step3`; Pi timings pending | [docs/step3-fast-advisor.md](docs/step3-fast-advisor.md) |
| URL, network-flow and DNS detectors; fusion; Android companion | planned | |

## Hardware and software

- Raspberry Pi 4 Model B, 4 GB, running Raspberry Pi OS Lite 64-bit (Debian 13)
- Python 3.10+ for the detectors and app; ExecuTorch for Llama

## Layout

| Folder | What is in it |
| --- | --- |
| `detectors/sms/` | SMS scam detector: India rules, baseline model, `Finding` wrapper |
| `advisor/` | Turns a `Finding` into advice: playbooks, Llama prompt, output validator; `llm_engine.py` + `llm_service.py` keep Llama loaded on the Pi |
| `app/` | FastAPI app: `POST /check` and a phone-friendly page |
| `tests/` | pytest suite (fake model and fake `llama_main`, so no torch is needed) |
| `deploy/` | Track B: export, Pi 4 build, benchmark script, test prompts |
| `scripts/` | `run_pi.sh`: starts the Llama service and the app on the Pi |
| `eval/` | Results for the report |
| `docs/` | Notes per step |

## Quick start (laptop)

```bash
pip install -r requirements.txt
pytest -q
python -m advisor.cli "Your SBI account is blocked, update KYC: http://sbi-kyc.example/v"
uvicorn app.server:app --port 8000
```

Open http://localhost:8000 and paste a message.

## Results so far

| What | Number | Where |
| --- | --- | --- |
| SMS detector, held-out F1 (6,053 unique messages) | 0.950, with 1.27% false alarms | [eval/results_sms.md](eval/results_sms.md) |
| Llama 3.2 1B SpinQuant INT4 on the Pi 4, 4 threads | prefill 12.7 tok/s, decode 4.4 tok/s, load 11.7 s | [eval/results_pi4.md](eval/results_pi4.md) |
| First 2-sentence advisor explanation on the Pi (`llama_main`) | ≈42.5 s end to end | [eval/results_pi4.md](eval/results_pi4.md) |

## Built with Llama

This project uses Llama 3.2 1B Instruct (SpinQuant INT4) under the [Llama 3.2 Community License](https://www.llama.com/llama3_2/license/). Model weights and exported `.pte` files are not stored in this repository. Download them from Meta or Hugging Face after accepting the licence; see [deploy/README.md](deploy/README.md).

## Scope

Defensive only. The repo has no attack or traffic-generation tools. The network detectors are tested by replaying labelled public captures on an isolated lab network.

# PS3 Guardian

On-device threat, phishing and scam detection for the **Arm Bharat AI-SoC Student Challenge, PS3**.

Specialist detectors flag scam SMS, phishing links and suspicious network behaviour in milliseconds. **Llama 3.2 1B**, running on the Raspberry Pi 4's Arm CPU through **ExecuTorch**, explains each alert in plain English or Hindi, and the app shows what to do next. Nothing leaves the device.

## Status

| Part | State | Details |
| --- | --- | --- |
| Track A: SMS scam detector baseline | done | [eval/results_sms.md](eval/results_sms.md) |
| Step 2: advisor vertical slice (SMS → advisor → app) | planned | |
| Track B: Llama 3.2 1B on the Pi 4 via ExecuTorch | planned | |
| URL, network-flow and DNS detectors; fusion; Android companion | planned | |

## Hardware and software

- Raspberry Pi 4 Model B, 4 GB, running Raspberry Pi OS Lite 64-bit (Debian 13)
- Python 3.10+ for the detectors and app; ExecuTorch for Llama

## Quick start (laptop)

```bash
pip install -r requirements.txt
python detectors/sms/train_baseline.py                      # trains on the bundled sample
python detectors/sms/train_baseline.py --predict "Your SBI KYC is pending, update at short.example/x"
```

## Scope

Defensive only. The repo has no attack or traffic-generation tools. The network detectors are tested by replaying labelled public captures on an isolated lab network.

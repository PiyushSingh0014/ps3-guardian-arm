# PS3 Guardian

On-device threat, phishing and scam detection for the **Arm Bharat AI-SoC Student Challenge, PS3**.

Specialist detectors flag scam SMS, phishing links and suspicious network behaviour in milliseconds, and check files that come in chats. **Llama 3.2 1B**, running on the Raspberry Pi 4's Arm CPU through **ExecuTorch**, explains each alert in plain English or Hindi, and the app shows what to do next. Nothing leaves the device.

## Status

| Part | State | Details |
| --- | --- | --- |
| Track A: SMS scam detector baseline | done | [eval/results_sms.md](eval/results_sms.md) |
| Step 2: advisor vertical slice (SMS → advisor → app) | done (laptop; template and `llama_main` backends) | [docs/step2-vertical-slice.md](docs/step2-vertical-slice.md) |
| Track B: Llama 3.2 1B on the Pi 4 via ExecuTorch | done: 12.7 tok/s prefill, 4.4 tok/s decode | [eval/results_pi4.md](eval/results_pi4.md), [deploy/README.md](deploy/README.md) |
| Step 3: fast advisor (persistent Llama service with a native C++ engine, prompt v4) | done on the Pi 4: explanations in 19–28 s per new alert | [docs/step3-fast-advisor.md](docs/step3-fast-advisor.md) |
| India SMS test set (227 real messages) and sender-aware scoring | measured | [eval/results_sms.md](eval/results_sms.md), [docs/india-sms-test-set.md](docs/india-sms-test-set.md) |
| Android companion: reads incoming SMS with their sender IDs | running on a Galaxy S25 with the Pi, and on two teammates' phones; their SMS collected on the Pi | [docs/android-companion.md](docs/android-companion.md) |
| SMS model v2: three classes (fraud, marketing, normal), learns from the team's labelled SMS; marketing trusted only from registered sender IDs | tools ready (update 33): labelling on the Pi, comparison with v1; with the public data alone, three classes change almost nothing (India set: 96% of scams caught, as v1); team results next | [docs/sms-model-v2.md](docs/sms-model-v2.md), [eval/results_sms.md](eval/results_sms.md#sms-model-v2-before-the-teams-messages) |
| Chats (RCS, WhatsApp) from unknown numbers, via notification access; several phones | running on the Galaxy S25 (opt-in) | [docs/android-companion.md](docs/android-companion.md), Parts F–G |
| Phishing link checker: official domains, brand rules, public phishing list, link model; links inside SMS and chats | done (update 9) | [eval/results_url.md](eval/results_url.md), [docs/url-detector.md](docs/url-detector.md) |
| Network detector: scans, floods, password guessing, beacons, DGA names, DNS tunnels, phishing look-ups, per-device normal; the Pi as the Wi-Fi hotspot for lab devices | done (update 10); live on the Pi's own lab Wi-Fi since 1 November 2026 (updates 12–16) | [eval/results_net.md](eval/results_net.md), [docs/network-detector.md](docs/network-detector.md) |
| ESP32 lab device: sensor readings on the Pi page, four harmless test modes | done: all four tests caught live (updates 14–16) | [docs/esp32-lab-device.md](docs/esp32-lab-device.md), [eval/results_net.md](eval/results_net.md) |
| Llama explanations for network alerts: a prompt of their own, written in the background | done on the Pi 4 (updates 17–23): all answers accepted (13 of 13); 21–31 s each, 86 s for the first after a message, repeats instant | [eval/results_net.md](eval/results_net.md), [docs/network-detector.md](docs/network-detector.md#llama-explanations) |
| Network alerts in the phone app: a notification per new alert, Llama's text when ready | built (update 20); install from Android Studio next | [docs/android-companion.md](docs/android-companion.md), Part H |
| Per-device risk view; messages meet network traffic: "Link from a scam message opened" | done: tested live on 3 November (updates 21–23) | [docs/network-detector.md](docs/network-detector.md) |
| Measuring on the Pi: false alarms on the lab Wi-Fi, CPU, memory, temperature | measured for hours (updates 24–28): after the fixes, no false alarm in 20,960 flows of busy use; a whole day still to do | [eval/results_net.md](eval/results_net.md), [docs/network-detector.md](docs/network-detector.md#measure-it-on-real-traffic) |
| File checker: files from chats (PDFs, Office files, apps, zips) on the Pi's page, by Share to PS3 Guardian, and app files named in chats | done (updates 29–32): 21 of 21 test files right; no false alarm on 521 ordinary PDFs; 53 of the team's 54 everyday files safe, 1 suspicious for a link, 20 ms per file on the Pi | [eval/results_files.md](eval/results_files.md), [docs/file-checker.md](docs/file-checker.md) |

## Hardware and software

- Raspberry Pi 4 Model B, 4 GB, running Raspberry Pi OS Lite 64-bit (Debian 13)
- Python 3.10+ for the detectors and app; ExecuTorch for Llama

## Layout

| Folder | What is in it |
| --- | --- |
| `detectors/sms/` | SMS scam detector: India rules, baseline model (v1), model v2 training and comparison (`train_v2.py`), `Finding` wrapper |
| `detectors/url/` | Phishing link checker: link parsing, brand and official-domain lists, public phishing list (SQLite), link model (`url_model.npz`) |
| `detectors/net/` | Network detector: flows from NFStream (live or pcap) or CIC-IDS2017 CSVs, behaviour rules, DNS checks, DGA model (`dga_model.npz`), per-device baseline, the monitor service |
| `detectors/files/` | File checker: the real type of a file from its first bytes, name tricks, APK permissions, PDF and Office signs, zips, links through the link checker |
| `advisor/` | Turns a `Finding` into advice: playbooks, Llama prompt, output validator; `llm_engine.py` + `llm_service.py` keep Llama loaded on the Pi |
| `app/` | FastAPI app: `POST /check` (a message or a link) and a phone-friendly page; `POST /url` for one link; `POST /file` for a file (checked in memory, never stored); `POST /sms` for the Android companion, with a traffic log; `GET /alerts` for network alerts; `/iot` for lab devices and their test modes |
| `android/` | Android companion: a complete Android Studio project (Kotlin). Forwards incoming SMS with their sender IDs to the Pi, and keeps them while the Pi is out of reach; shows the Pi's network alerts as notifications; checks files shared to it (Share to PS3 Guardian) |
| `esp32/` | Lab device: Arduino sketch for the ESP32 on the IoT Pro Kit. Sends its sensor readings to the Pi; harmless test modes imitate infected IoT devices for the network detector ([docs/esp32-lab-device.md](docs/esp32-lab-device.md)) |
| `tests/` | pytest suite (fake model and fake `llama_main`, so no torch is needed) |
| `deploy/` | Track B: export, Pi 4 build, benchmark script, test prompts |
| `scripts/` | `run_pi.sh`: starts the Llama service and the app on the Pi; `install_service.sh`: starts them at every boot (systemd); `sms_traffic.py`: labels, exports and measures the companion's traffic log; `get_url_data.py`: downloads the link checker's lists; `install_netmon.sh`: the network monitor service; `setup_gateway.sh`: the Pi as a Wi-Fi hotspot, with automatic undo; `net_traffic.py`: label the monitor's alerts and count false alarms per day; `pi_usage.py`: CPU, memory and temperature; `make_file_samples.py`: harmless test files for the file checker; `check_files.py`: check a folder of files and count false alarms |
| `eval/` | Results for the report |
| `docs/` | Notes per step |

## Quick start (laptop)

```bash
pip install -r requirements.txt
pytest -q
python scripts/get_url_data.py          # optional: the public phishing list and the top websites (~20 MB)
python -m advisor.cli "Your SBI account is blocked, update KYC: hxxp://sbi-kyc-update.xyz/v"
uvicorn app.server:app --port 8000
```

Open http://localhost:8000 and paste a message or a link.

## Results so far

| What | Number | Where |
| --- | --- | --- |
| SMS detector, held-out F1 (6,053 unique messages) | 0.950, with 1.27% false alarms | [eval/results_sms.md](eval/results_sms.md) |
| SMS detector on 227 real Indian messages, text only | 94% of fraud caught, but 64% of normal messages flagged | [eval/results_sms.md](eval/results_sms.md) |
| Same, with registered sender IDs (projection) | 96% of fraud caught, 4% of normal messages flagged | [eval/results_sms.md](eval/results_sms.md) |
| Link checker on brand-new phishing sites (held out, no lists) | 81% caught; 7.6% of popular websites flagged, 1.1% called dangerous | [eval/results_url.md](eval/results_url.md) |
| Held-out phishing hosts using an Indian brand's name | 20 of 21 flagged; 0.3% of popular `.in` websites called dangerous | [eval/results_url.md](eval/results_url.md) |
| Network detector on CIC-IDS2017 (5 days, 2.8M flows) | all 10 network-level attacks detected, 7 within the first minute; 46 false alarms in 40.7 h without beacon alerts (162 with) | [eval/results_net.md](eval/results_net.md) |
| Lab Wi-Fi, busy use with the update 27 rules | no false alarm in 1.1 h of traffic and 20,960 flows (the first busy hour had 5, all fixed) | [eval/results_net.md](eval/results_net.md) |
| File checker on 21 harmless test files | all 21 right: 6 safe, 15 dangerous (apps dressed as documents, PDF code, macros, remote templates, DDE, fake sign-in pages, phishing links) | [eval/results_files.md](eval/results_files.md) |
| File checker on 521 ordinary PDFs (TeX Live's manuals, LibreOffice, Chromium, qpdf) | no false alarm (update 29: 4, fixed in update 30) | [eval/results_files.md](eval/results_files.md) |
| File checker on the team's 54 everyday files, on the Pi | 53 safe, 1 suspicious (a link in an e-book), 0 dangerous; 20 ms per file | [eval/results_files.md](eval/results_files.md) |
| DGA model, held-out names | 89.8% of machine-made names caught, 0.35% of real names flagged | [eval/results_net.md](eval/results_net.md) |
| Llama 3.2 1B SpinQuant INT4 on the Pi 4, 4 threads | prefill 12.7 tok/s, decode 4.4 tok/s, load 11.7 s | [eval/results_pi4.md](eval/results_pi4.md) |
| First 2-sentence advisor explanation on the Pi (`llama_main`) | ≈42.5 s end to end | [eval/results_pi4.md](eval/results_pi4.md) |

## Built with Llama

This project uses Llama 3.2 1B Instruct (SpinQuant INT4) under the [Llama 3.2 Community License](https://www.llama.com/llama3_2/license/). Model weights and exported `.pte` files are not stored in this repository. Download them from Meta or Hugging Face after accepting the licence; see [deploy/README.md](deploy/README.md).

## Scope

Defensive only. The repo has no attack or traffic-generation tools. The network detector is measured on labelled public data (CIC-IDS2017 flow records) and on the Pi's own lab network; it reads connection summaries, never the content of traffic. The file checker's test files are harmless files made for it; no real malware is used.

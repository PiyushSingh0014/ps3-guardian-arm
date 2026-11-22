# Home Hub (Raspberry Pi 4)

**What it is for:** protecting every device on the home Wi-Fi, including the cameras, plugs and sensors that cannot run
any security app. The hub is the home's Wi-Fi hotspot and DNS server, so every device's traffic passes through it.

**What it does:** checks messages, links and files sent from the phone app or its web page; watches the traffic of every
device; blocks scam websites for the whole home; and explains every alert with Llama 3.2 1B through ExecuTorch on the
Pi's Arm CPU. Everything in this folder runs on the Pi, with no cloud.

| Folder | What it does | Use it to |
| --- | --- | --- |
| [`app/`](app/) | The app server and web page (FastAPI, HTTPS with a pinned certificate, pairing token), DNS blocking, the Llama files a paired phone copies, the message log, the lab devices | serve the phone and the page: `python -m app.serve` (started by the service) |
| [`detectors/`](detectors/) | The checkers: [`sms/`](detectors/sms/) messages and sender IDs, [`url/`](detectors/url/) links, [`files/`](detectors/files/) PDF, Office, APK and zip files, [`net/`](detectors/net/) the network monitor | judge a message, link, file or device's traffic in milliseconds |
| [`advisor/`](advisor/) | The playbooks (steps for every alert), the prompts, the Llama service and engines, the grounding checker, the grading tool | turn a finding into advice at once and an explanation a few seconds later |
| [`llama-engine/`](llama-engine/README.md) | How Llama 3.2 1B was exported with ExecuTorch, and our C++ engine built for the Pi 4's Armv8.0 CPU | build the engine the Llama service runs |
| [`scripts/`](scripts/README.md) | The hotspot, the services, DNS blocking, downloads, measuring tools, the export of the checks to the phone, the accuracy test | install and measure the hub |
| [`tests/`](tests/) | 379 automated tests | check everything: `python -m pytest` |

## Run it on a Raspberry Pi

All commands run from this folder (`cd ~/ps3-guardian/home-hub`). The guides give every step:

1. **The hotspot:** `bash scripts/setup_gateway.sh` makes the Pi the Wi-Fi `PS3-Guardian-Lab`
   ([docs/network-detector.md](../docs/network-detector.md)).
2. **Llama:** export the model and build the C++ engine ([llama-engine/README.md](llama-engine/README.md),
   [docs/step3-fast-advisor.md](../docs/step3-fast-advisor.md)).
3. **The app server and Llama, at every boot:** `LLAMA_SERVER_BIN=... bash scripts/install_service.sh`
   (service `ps3-guardian`).
4. **The network monitor, at every boot:** `bash scripts/install_netmon.sh` (service `ps3-netmon`).
5. **DNS blocking:** `bash scripts/setup_dns_block.sh` ([docs/dns-blocking.md](../docs/dns-blocking.md)).
6. **Pair a phone** with the Sajag app ([docs/android-companion.md](../docs/android-companion.md)).

On a laptop, without a Pi: `pip install -r requirements.txt`, then `python -m pytest -q`, or
`uvicorn app.server:app --port 8000` and open http://localhost:8000.

## Files that are not in git

They live in this folder on the Pi and are never committed: `data/` (the phishing list, the block list, the consented
message log and its labels, the grading answers), `logs/`, and the trained SMS model
`detectors/sms/sms_baseline.joblib`. Llama's model file (about 1 GB) stays outside the repository (Meta's licence).

## Moving a Pi from the old layout

Before update 53 these folders were at the top of the repository. On a Pi that still runs the old layout, after
bringing in the new one (`git merge --ff-only layout`), run once from the repository's top folder:

```bash
cd ~/ps3-guardian
bash home-hub/scripts/migrate_layout.sh
```

It stops the services, moves the files git does not track into `home-hub/`, keeps everything else from the old
folders in `~/ps3-guardian-old-layout/`, re-installs the services with the new paths, points DNS blocking at the new
list, and starts everything again.

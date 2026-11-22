# Scripts

Run them from the hub's folder (`cd ~/ps3-guardian/home-hub` on the Pi). Each script explains its options with `--help` or at
its top.

## The Home Hub (Raspberry Pi)

| Script | What it does |
| --- | --- |
| `setup_gateway.sh` | Makes the Pi the Wi-Fi hotspot (`PS3-Guardian-Lab`, 10.42.0.1), with internet from a phone by USB; undoes itself after 10 minutes unless confirmed |
| `install_service.sh` | Starts the app server and the Llama service at every boot (systemd service `ps3-guardian`) |
| `run_pi.sh` | What the service runs: the Llama service, then the app (HTTPS on port 8443) |
| `install_netmon.sh` | Starts the network monitor at every boot (systemd service `ps3-netmon`) |
| `setup_dns_block.sh` | DNS blocking on the hotspot, with `--status`, `--keep` and `--undo` |
| `dns_block_helper.py` | The small root helper that turns the block list into dnsmasq's list (installed by `setup_dns_block.sh`) |
| `migrate_layout.sh` | Once, on a Pi that ran the old layout (before update 53): moves its data, logs and model into `home-hub/` and re-installs the services |

## Data

| Script | What it does |
| --- | --- |
| `get_url_data.py` | Downloads the link checker's lists (Phishing.Database, top sites) and, if asked, its training data |
| `get_iot23.sh` | Downloads IoT-23 captures for the replay |
| `make_file_samples.py` | Makes harmless test files for the file checker |

## Measuring

| Script | What it does |
| --- | --- |
| `accuracy_test.py` | The accuracy test on labelled message sets, as the phone decides |
| `sms_traffic.py` | Labels and measures the real messages the phones forwarded (`label`, `label --flagged`, `review`, `measure`) |
| `net_traffic.py` | Labels network alerts and measures false alarms per day on the lab Wi-Fi |
| `check_files.py` | Runs the file checker over a folder: false alarms on ordinary files |
| `pi_usage.py` | CPU, memory and temperature of the hub's services |

## The phone

| Script | What it does |
| --- | --- |
| `export_phone_guard.py` | Exports the hub's message and link checks (model, rules, lists, playbooks, prompt) into the app's `assets/guard/` |
| `check_phone_guard.py` | Checks that the phone's Kotlin code decides exactly as the hub's Python code (`inputs`, `compare`) |

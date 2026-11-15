# DNS blocking: the Pi stops scam websites from opening on its Wi-Fi

## Why

Until update 40 the Pi only detected: "Link from a scam message opened" came after the device had already loaded the page, and the steps were advice only (the hard review, gap 2.8). The Pi is the DNS server of every device on its hotspot, so it can refuse to look a website up. Then the page does not open, on any device on `PS3-Guardian-Lab`.

## What is blocked

| Blocked | For how long | Source in the list |
| --- | --- | --- |
| The websites of a message the Pi judged **dangerous** (SMS, chat, the page, a shared file) | 7 days | `message` |
| A website a device **looked up** that is on the public phishing list, or that puts a brand's name on someone else's site (the "Device opened a phishing website" alert) | 7 days | `network` |
| A website from a flagged message that a device then **opened** ("Link from a scam message opened"), even if the message was only suspicious | 7 days | `network` |
| A website you **block by hand** on the Pi's page | until you unblock it | `page` |

A block covers the name and every name under it: `kyc-check.xyz` also blocks `sbi.kyc-check.xyz`.

**Never blocked:** official websites (`.bank.in`, `.gov.in`, the brands' own domains), the 10,000 most visited websites, link shorteners, chat links, shared services (Google Drive, forms, free hosting) and IP addresses: the same exceptions as the watch list. Blocking one of them would cut off everyone. The page says so if you try.

**Undo:** on the Pi's page, under **Blocked websites**, tap **Unblock**. A website you unblock is remembered: it is not blocked automatically again, even if another message carries it (blocking it by hand still works).

## How it works

```
app (dangerous message, the page)  ─┐
                                    ├─► data/net/blocklist.json ─► systemd notices the change (ps3-dnsblock.path)
network monitor (phishing look-up) ─┘                              │
                                                                   ▼
                                  root helper /usr/local/lib/ps3-guardian/dns-block
                                  writes /var/lib/ps3-guardian/blocked.servers ("server=/name/" lines)
                                  and sends SIGHUP to the hotspot's dnsmasq
                                                                   │
                                                                   ▼
                                  dnsmasq answers NXDOMAIN for the name and every name under it
```

- **No sudo for the app or the monitor.** They only write the list. systemd runs the helper as root when the list changes, and every hour so that blocks end on time.
- **The helper trusts nothing in the list.** It reads only the paths in `/etc/ps3-guardian/dns-block.json`, which only root can change. It refuses a list that is a link or not owned by the app's user, keeps only well-formed website names (at most 1,000), writes one file and signals one process.
- **One setting for dnsmasq.** NetworkManager's hotspot reads `/etc/NetworkManager/dnsmasq-shared.d/`, where `scripts/setup_gateway.sh` already writes a setting. `setup_dns_block.sh` adds `ps3-block.conf` with one line, `servers-file=/var/lib/ps3-guardian/blocked.servers`, a file dnsmasq reads again on SIGHUP.
- **The alerts say it.** When a device looks up a website that is already blocked, the alert says "the Pi's DNS refused it, so it did not open". When the alert itself blocks the website, it says "the Pi has now blocked this website on its Wi-Fi". Llama sees these words like any other evidence.

## Set it up (once, on the Pi)

The hotspot must be on (`bash scripts/setup_gateway.sh --status` says `Hotspot: ON`).

```bash
cd ~/ps3-guardian
bash scripts/setup_dns_block.sh
```

It installs the helper, the systemd units and the setting, then asks before restarting the hotspot once, so that its dnsmasq reads the setting. The devices on the hotspot lose the Wi-Fi for a few seconds; an SSH session over it may stop responding. After about 30 seconds, from the laptop on `PS3-Guardian-Lab`:

```bash
ssh arrehinus@10.42.0.1                                # if the session stopped
cd ~/ps3-guardian && bash scripts/setup_dns_block.sh --status
```

`--status` shows the test that ran after the restart (`logs/dns_block_test.log`): it blocks `example.org` (IANA's example domain) for a moment, checks that the Pi's DNS answers NXDOMAIN, unblocks it and checks that it answers again. If the test passed and a phone on the hotspot still opens websites:

```bash
bash scripts/setup_dns_block.sh --keep
```

**Safety net:** without `--keep` within 10 minutes, the setting is removed by itself and the hotspot restarts with plain DNS, as `setup_gateway.sh` does for the hotspot. To remove everything later: `bash scripts/setup_dns_block.sh --undo`.

## Try it

1. On the Pi's page, under **Blocked websites**, type `example.org` and tap **Block**.
2. On a phone on `PS3-Guardian-Lab`, open `http://example.org`: "This site can't be reached". On the Pi: `python3 -m app.dns_block check example.org` says NXDOMAIN.
3. Tap **Unblock** on the page: the site opens again (a browser may keep its old answer for a minute).

With the ESP32: its "Fake bank site" test looks up `sbi-kyc-update-verify.xyz` every 30 s. The first alert blocks it ("the Pi has now blocked this website on its Wi-Fi"); the website then appears under **Blocked websites**, and the next alert about it, 10 minutes later, says it did not open.

From the command line (on the Pi, in `~/ps3-guardian`): `python3 -m app.dns_block list`, `unblock NAME`, `check NAME`, `selftest`. `block NAME` refuses official and popular websites as the page does, so it needs the link checker: run it after `source ~/ps3-venv/bin/activate`.

If `example.org` is still blocked by hand when the self-test runs (for example after "Try it"), the test only checks that the Pi's DNS refuses it, and leaves the block in place.

## What it cannot do

- **Devices that do not use the Pi's DNS:** Android's Private DNS set to a named provider, browsers with their own secure DNS, IoT devices with a fixed DNS server. Redirecting all DNS traffic to the Pi, and blocking known secure-DNS servers, is Phase 2.
- **The first look-up of a new phishing site** has already been answered when the monitor sees it: that device may have the page open. Every look-up after the block, from any device, fails.
- **Answers devices already keep:** a phone that looked the site up just before the block may reach it until its own cache expires (usually minutes).
- **Links to an IP address,** and websites on shared services, which are never blocked whole.
- **Phones on mobile data:** only devices on the Pi's Wi-Fi use its DNS.

## Files

| File | What |
| --- | --- |
| `data/net/blocklist.json` | The list: written by the app and the monitor ([app/dns_block.py](../app/dns_block.py)) |
| `/var/lib/ps3-guardian/blocked.servers` | What dnsmasq reads, written by the helper |
| `/etc/NetworkManager/dnsmasq-shared.d/ps3-block.conf` | The one setting for the hotspot's dnsmasq |
| `/usr/local/lib/ps3-guardian/dns-block`, `/etc/ps3-guardian/dns-block.json` | The helper ([scripts/dns_block_helper.py](../scripts/dns_block_helper.py)) and its settings |
| `ps3-dnsblock.service`, `.path`, `.timer` | systemd: apply on change, and every hour |

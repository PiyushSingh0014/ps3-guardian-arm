# Android companion: read incoming SMS with their sender IDs

## Why

On the India test set, the sender ID decides most false alarms:

- **Text only:** 64% of normal messages are flagged.
- **With the real registered sender ID** (projected): about 4%.

Typed names don't work, so the app must read the ID itself. An Android app gets the raw ID with every SMS:

- `JD-HDFCBK-S` for a business
- `+919812345678` for a phone number

The first real message through the app (2026-10-25) shows the effect: an Airtel pack notice from `AE-AIRTEL-S` scored **0.856 (dangerous)** on its text alone and **0.106 (safe)** with its sender ID.

```
incoming SMS ──> Android app ──(Wi-Fi hotspot, POST /sms + pairing token)──> Pi
                    ▲                                                     │ detector + sender scoring
                    └──────────── verdict + advice (alert) ◄──────────────┤ Llama explanation (later)
                                                                          └─> logs/sms_traffic.jsonl
```

Chat messages (RCS "chat features" in Messages, WhatsApp) are not SMS: Android passes them to no other app. The app can still check them through the notifications the chat apps show, if you switch that on (Part F), and only for senders who are not in your contacts.

Since update 9, the Pi also checks every link in a message: official sites, brand names on other people's sites, and the public list of phishing sites. The app needs no change for this. See [url-detector.md](url-detector.md).

## Part A: the Pi

### First time only: start automatically

So that the app comes back by itself after the Pi restarts (for example after a power dip):

```bash
cd ~/ps3-guardian
bash scripts/install_service.sh
```

It installs a systemd service, `ps3-guardian`, that runs `scripts/run_pi.sh` at every boot and again if it stops with an error. From then on:

| To | Run |
| --- | --- |
| restart (for example after an update) | `sudo systemctl restart ps3-guardian` |
| see if it runs | `systemctl status ps3-guardian --no-pager` |
| read the log (now appended, not overwritten) | `tail -n 30 ~/ps3-guardian/logs/app.log` |

Don't start `scripts/run_pi.sh` by hand any more: a second copy cannot use port 8000.

### Each update

1. Copy the bundle from the laptop to the Pi. In **PowerShell** (`PS C:\Users\Lenovo>`), for example for update 6:

   ```powershell
   scp $HOME\Downloads\ps3-guardian-update6.bundle arrehinus@10.140.209.76:~/
   ```

2. On the Pi (`arrehinus@ps3-guardian`), pull it, push it to GitHub (the `step3` branch and `main`, the branch GitHub shows first) and restart the app:

   ```bash
   cd ~/ps3-guardian
   git pull --no-rebase --no-edit ~/ps3-guardian-update6.bundle step3
   git push origin step3 step3:main
   sudo systemctl restart ps3-guardian
   for i in $(seq 40); do curl -sf http://127.0.0.1:8000/health > /dev/null && break; sleep 5; done
   grep "pairing token" logs/app.log | tail -n 1
   ```

   The loop waits up to about 3 minutes while Llama loads. `--no-edit` stops git from opening an editor for the merge message (your Pi has merge commits of its own). If an editor does open, save and close it: in nano, Ctrl+X, Y, Enter.

3. The last line shows the two values the app needs:
   - the Pi address, for example `http://10.140.209.76:8000`
   - the pairing token, 8 characters. It is created once and kept in `~/.ps3_guardian_token`.

## Part B: build the app (laptop)

1. **Install Android Studio** (the current stable version) from developer.android.com/studio.

2. **Get the project.** The repo's `android/` folder is the complete Android Studio project (package `com.example.ps3guardian`). Either clone the repo, or on GitHub choose **Code → Download ZIP** and unzip it.

3. **Open it:** File → **Open** → choose the `android` folder (not the repo's top folder). Android Studio downloads Gradle and the libraries the first time; wait until the sync finishes.

   Two warnings are expected and can be left alone: "Not targeting the latest versions of Android" (the target stays at 36 on purpose: apps targeting Android 17, API 37, receive OTP-like SMS three hours late and need an extra local-network permission) and "Use version catalog instead".

4. **Build → Make Project** (Ctrl+F9; called Assemble Project in some versions). It should end with BUILD SUCCESSFUL. If it doesn't, send the first error line.

**Updating the app later:** get the new version of the repo (pull, or download the ZIP again), or copy the changed `.kt` files from `android/app/src/main/java/com/example/ps3guardian/` over your copies, and press **Run ▶**. The app keeps its settings and its list.

<details>
<summary>How the project was made (only needed to make it again from scratch)</summary>

New Project → *Empty Views Activity*: name `PS3 Guardian`, package `com.example.ps3guardian` (Android Studio's suggestion), Kotlin, minimum SDK API 26, Kotlin DSL. Then in `app/build.gradle.kts`: `targetSdk = 36` and `implementation("androidx.work:work-runtime-ktx:2.12.0")`; then the app's files copied into `app/src/main/` (manifest, the 8 `.kt` files, `res/layout/activity_main.xml`, `res/xml/network_security_config.xml`). If you choose another package name, change the first line (`package ...`) of the 8 `.kt` files to match (Edit → Find → Replace in Files).

</details>

## Part C: install it on your phone

1. **Developer options:** Settings → About phone → Software information → tap **Build number** 7 times. Then Settings → Developer options → turn on **USB debugging** (under the "Debugging" heading).
2. **Samsung only:** Settings → Security and privacy → **Auto Blocker** → off while you install. It blocks commands over USB and greys out USB debugging. Turn it back on afterwards; the installed app keeps working.
3. **Install:** connect the phone by USB, tap **Allow** on the "USB debugging" prompt, pick the phone in Android Studio's device box (not an emulator: it has no SIM) and press **Run ▶**. If Play Protect asks, choose to install anyway: it is your own app.

> Install it only this way. Don't send the APK through WhatsApp, Drive or a browser:
> - In India, Play Protect blocks apps installed that way when they ask for SMS permissions.
> - Android 15+ also locks the SMS permission for apps installed from a file.

## Part D: set it up

1. **Connect your phone to the Pi,** in one of two ways:
   - **The Pi is on a phone's hotspot:** your phone is that hotspot or is connected to it. Use the Pi's address there, for example `http://10.140.209.76:8000`.
   - **The Pi is the hotspot itself** ([network-detector.md](network-detector.md), part 2): join the Wi-Fi `PS3-Guardian-Lab` and use `http://10.42.0.1:8000`. The exception is the phone that gives the Pi internet over USB: it stays off that Wi-Fi, and its app uses the USB address `setup_gateway.sh --keep` prints.
2. **Pi address, token and phone name:** type the address and the pairing token from Part A, and a short **phone name** (for example `A`; every phone gets its own, see Part G). Tap **Save**, then **Test connection**. You should see "Connected. Advisor: llama_service."
3. **Permissions:** tap **Allow SMS and notifications** and allow both.
   - If SMS cannot be allowed or says "restricted setting": go to App info → **⋮** → **Allow restricted settings**.
   - Then go to Permissions → **SMS** → Allow.
4. **Battery:** App info → Battery → **Unrestricted**, so checks still run when the phone is idle.
5. **Test without SMS:** tap **Send a test scam**. A "DANGEROUS" alert appears, and about 30 s later Llama's explanation replaces its text. Tests are not logged on the Pi.
6. **Test with a real SMS:** send yourself an SMS with a link from the Messages app (for example "check this http://example.com"), or ask a friend to send one. Your mobile operator usually answers with an SMS of its own, from a registered sender ID. A line appears in the app's list for each. On the Pi:

   ```bash
   tail -n 2 ~/ps3-guardian/logs/sms_traffic.jsonl
   ```

   A message from a phone number shows `"sender": "mobile"`; business SMS (OTPs, bank alerts, your operator) show their sender ID, for example `"AE-AIRTEL-S"`.

## Part E: collect real traffic and measure

1. **Collect** for about a week. Every incoming SMS, and every chat if you switched chats on (Part F), is checked and logged with the phone's name. The Pi does not have to stay on all the time: see the next point.
   - **Away from the Pi:** an SMS that arrives while the phone cannot reach the Pi is kept on the phone and shows "WAITING for the Pi". It is sent by itself once the Pi can be reached again: within about 15 minutes, or at once when you open the app. Its line then says "checked later". Up to 500 messages are kept, only in the app's private storage, until the Pi has checked them.
   - **Hotspot:** when you come back, the Pi reconnects to your phone's hotspot by itself, as long as the hotspot is on. If your phone switches the hotspot off when nothing is connected, turn that timeout off in the hotspot settings.
   - **Privacy on the Pi:**
     - Digits are replaced by `#`.
     - Phone numbers are not stored, nor the names of chat senders.
     - The text of safe messages from phone numbers (mostly personal chats) is not stored, nor the text of any chat that was judged safe.
   - **OTPs:** on Android 17 and later, OTP messages that carry an app code (the 11-character string at the end) reach the app three hours late. Android protects them, and that is fine for this test.
2. **Export the log** on the Pi:

   ```bash
   cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
   python scripts/sms_traffic.py export ~/traffic.csv
   ```

3. **Label it.** Copy the file to the laptop. In PowerShell:

   ```powershell
   scp arrehinus@10.140.209.76:~/traffic.csv $HOME\Downloads\
   ```

   Open it in Excel and fill the `label` column with `smishing`, `spam` or `ham`; leave a row empty if you are unsure. Save it as **CSV UTF-8**.
   - With several phones, each person labels the rows of their own phone (the `device` column).
   - A row without text is a safe message from a phone number or a safe chat: if you need to, find it on the phone by its `time`.
4. **Measure.** Copy it back and run:

   ```powershell
   scp $HOME\Downloads\traffic.csv arrehinus@10.140.209.76:~/traffic.csv
   ```

   ```bash
   python scripts/sms_traffic.py measure ~/traffic.csv
   ```

   It prints flagged messages per label, text only vs with the sender ID, for all messages and then separately for SMS and chats, and how many came from each phone: the real-traffic numbers that replace the projection in `eval/results_sms.md`.
5. **Clean up:** after measuring, delete the log on the Pi with `rm ~/ps3-guardian/logs/sms_traffic.jsonl`.

## Part F: chats (RCS and WhatsApp)

Android never passes chat messages to other apps, but it shows them the notifications that chat apps post, if you allow **Notification access**. The app uses that to check chats:

- **Which apps:** Messages (Google Messages and Samsung Messages: RCS chats and MMS) and WhatsApp. Each has its own switch, off until you turn it on.
- **Which senders:** only senders shown as a phone number, that is, people who are not in your contacts, where scam chats come from. Chats from your contacts and from businesses are ignored and never leave the phone, unless you turn on the testing switch.
- **On the Pi:** a chat is scored on its text, plus the same extra weight as an SMS from a phone number when it has a link, money or urgency. Its text is stored only if it was flagged (digits masked), and its sender only as `mobile` (or `name` while testing).
- **Not seen:** chats whose notification you have turned off or muted, and notifications Android hides from apps like this one (on Android 15 and later, notifications that carry an OTP).
- An SMS also shows up as a Messages notification; it is checked once, as an SMS.

1. In the app, tick **Check chats in Messages (RCS)** and, if you want, **Check WhatsApp chats**.
2. Tap **Allow notification access**, find **PS3 Guardian** and allow it. Android warns that the app can read notifications: that is what it needs. If the switch is grey or says "restricted setting": App info → **⋮** → **Allow restricted settings**, then try again.
3. Back in the app, the line under the button says which chats are being checked.
4. **Test:** tick **Also check chats from saved contacts (for testing)** and ask a teammate to send you an RCS chat (or a WhatsApp message) with a link, for example `check this http://example.com`. About 5 seconds after it arrives, a line `[Messages] <name> …` appears in the app's list, with an alert if it was flagged. On the Pi, `tail -n 1 ~/ps3-guardian/logs/sms_traffic.jsonl` shows `"channel": "chat"`. Then untick the testing switch.

## Part G: more phones

More phones give more, and more varied, messages: other banks, operators and apps. For each teammate's Android phone (iPhones don't let apps read SMS):

1. **Install** the app the same way: Part C, over USB from Android Studio, never by sending the APK.
2. **Set it up** as in Part D, with the **same Pi address and token** and a **different phone name** (for example `B`, `C`). Part F (chats) is up to them.
3. **Collect:** their messages wait on their phone (up to 500) until it is on the Pi's hotspot, then go to the Pi by themselves.
4. **Agree first:** the Pi keeps sender IDs, verdicts and the text of flagged messages with digits masked; never phone numbers, chat senders' names or the text of safe personal messages. They can uninstall the app at any time.

When labelling (Part E), each person labels their own phone's rows: they know best whether a message really came from their bank.

## If something goes wrong

| What you see | Fix |
| --- | --- |
| "Cannot reach the Pi" | Same hotspot? On the Pi, `curl -s http://127.0.0.1:8000/health` must print `{"ok":true,...}`; if not, `systemctl status ps3-guardian --no-pager` and `tail -n 30 logs/app.log`. The Pi's address is in `hostname -I`. |
| `HTTP 401` | The token is wrong: `cat ~/.ps3_guardian_token` on the Pi |
| `HTTP 503` | The Pi has no token: `sudo systemctl restart ps3-guardian` |
| "WAITING for the Pi" | Normal while the phone cannot reach the Pi; the message is sent later by itself. Many of them: check the Pi as for "Cannot reach the Pi". |
| No alert, but the list shows the message | It was judged safe (no alert for safe messages), or notifications are off for the app |
| Nothing at all when an SMS arrives | SMS permission (Part D, step 3) and battery Unrestricted (step 4). Chats are checked only as set up in Part F. |
| A chat is not checked | Is its app ticked, and does the line under "Allow notification access" say chats are being checked? Is the sender shown as a phone number (not in your contacts)? Are notifications on for that chat? The check runs about 5 seconds after the notification. |
| `Unresolved reference 'R'` and "Package directive does not match the file location" | The `.kt` files were copied into a project with another package name: change their first line to that package (see "How the project was made" in Part B), then build again. |
| Emulator: "not enough disk space" | You don't need the emulator: install on your phone (Part C). |
| Other build error in Android Studio | Send the first error line |

## Sources for the Android rules above

- Play Protect in India blocks sideloaded apps that request SMS permissions: [9to5Google, Oct 2024](https://9to5google.com/2024/10/03/google-blocking-sideloaded-apps-india/).
- Android 15 restricts the SMS permission for apps installed from a file: [Android Authority](https://androidauthority.com/android-15-restricted-settings-sideloading-3481098); how to allow it: [textbee.dev](https://textbee.dev/blog/android-15-send-sms-permission-guide).
- OTP SMS delays: [Android 17 behaviour changes](https://developer.android.com/about/versions/17/behavior-changes-all).
- Local network permission for apps targeting Android 17: [Android developers](https://developer.android.com/privacy-and-security/local-network-permission).
- Samsung Auto Blocker: [Samsung support](https://www.samsung.com/sg/support/mobile-devices/protect-your-galaxy-device-with-the-new-auto-blocker-feature); it greys out USB debugging: [Samsung developer forum](https://forum.developer.samsung.com/t/s24-ultra-developer-option-usb-debugging-greyed-out/29526?page=2).
- WorkManager versions: [release notes](https://developer.android.com/jetpack/androidx/releases/work).

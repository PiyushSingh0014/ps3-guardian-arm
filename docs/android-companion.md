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

Since update 20, the app also shows the Pi's **network alerts**: what its network monitor finds on the lab Wi-Fi, for every device there, as notifications (Part H).

Since update 29, a **file** that came in a chat (a PDF, an Office file, an app, a zip) can be shared to the app and is checked on the Pi; an app file sent by a saved contact gives an alert by itself (Part I).

Since update 46 (app 3.0), the app is called **Sajag** (सजग), with four pages, a screen for every alert and a set-up in three steps. The buttons the older parts of this guide name have moved: Part M says where.

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
   hostname -I; cat ~/.ps3_guardian_token; cat ~/.ps3_tls_fingerprint
   ```

   The loop waits up to about 3 minutes while Llama loads. `--no-edit` stops git from opening an editor for the merge message (your Pi has merge commits of its own). If an editor does open, save and close it: in nano, Ctrl+X, Y, Enter.

3. The last three lines show the values the app needs:
   - the Pi address: the first address `hostname -I` prints, as `https://<address>:8443` (on the lab Wi-Fi, `https://10.42.0.1:8443`). Since update 39 the phones and the page use HTTPS (Part J).
   - the pairing token, 22 characters, created once and kept in `~/.ps3_guardian_token`. Every request to the Pi needs it, from the phones and from the page in a browser (the page asks for it once). It is never printed in the log.
   - the fingerprint of the Pi's HTTPS certificate, 16 groups of 4 characters, made once and kept in `~/.ps3_tls_fingerprint`. Each phone compares it once, when it pairs (Part J).

   **Since update 36** the token is longer: after the first restart with update 36, type the new one into each phone's app (**Save**, then **Test connection**) and once into the page. Until then the phones keep their messages and send them later. The old short token now works only for the ESP32's readings ([esp32-lab-device.md](esp32-lab-device.md)).

## Part B: build the app (laptop)

1. **Install Android Studio** (the current stable version) from developer.android.com/studio.

2. **Get the project.** The repo's `android/` folder is the complete Android Studio project (package `com.ps3guardian.app`; `com.example.ps3guardian` until update 39). Either clone the repo, or on GitHub choose **Code → Download ZIP** and unzip it.

3. **Open it:** File → **Open** → choose the `android` folder (not the repo's top folder). Android Studio downloads Gradle and the libraries the first time; wait until the sync finishes.

   Two warnings are expected and can be left alone: "Not targeting the latest versions of Android" (the target stays at 36 on purpose: apps targeting Android 17, API 37, receive OTP-like SMS three hours late and need an extra local-network permission) and "Use version catalog instead".

4. **Build → Make Project** (Ctrl+F9; called Assemble Project in some versions). It should end with BUILD SUCCESSFUL. If it doesn't, send the first error line.

**Updating the app later:** get the new version of the repo (pull, or download the ZIP again) and press **Run ▶**. The app keeps its settings and its list. Copy the whole `android` folder, not only `app/src/main`: update 39 also changed `app/build.gradle.kts`.

**Update 39 installs a new app.** Its package name changed, so Android sees another app: the old one stays until you remove it, and both would send each SMS to the Pi. Before installing, open the old app and wait until no message is waiting for the Pi (the list says so), then uninstall it (long-press its icon → **Uninstall**). The new app starts empty: set it up again as in Part D.

<details>
<summary>How the project was made (only needed to make it again from scratch)</summary>

New Project → *Empty Views Activity*: name `PS3 Guardian`, package `com.ps3guardian.app`, Kotlin, minimum SDK API 26, Kotlin DSL. Then in `app/build.gradle.kts`: `targetSdk = 36` and `implementation("androidx.work:work-runtime-ktx:2.12.0")`; then the app's files copied into `app/src/main/` (manifest, the `.kt` files, `res/layout/activity_main.xml`, `res/xml/network_security_config.xml`). If you choose another package name, change the first line (`package ...`) of every `.kt` file to match (Edit → Find → Replace in Files).

</details>

## Part C: install it on your phone

1. **Developer options:** Settings → About phone → Software information → tap **Build number** 7 times. Then Settings → Developer options → turn on **USB debugging** (under the "Debugging" heading).
2. **Samsung only:** Settings → Security and privacy → **Auto Blocker** → off while you install. It blocks commands over USB and greys out USB debugging. Turn it back on afterwards; the installed app keeps working.
3. **Install:** connect the phone by USB, tap **Allow** on the "USB debugging" prompt, pick the phone in Android Studio's device box (not an emulator: it has no SIM) and press **Run ▶**. If Play Protect asks, choose to install anyway: it is your own app.

> Install it only this way. Don't send the APK through WhatsApp, Drive or a browser:
> - In India, Play Protect blocks apps installed that way when they ask for SMS permissions.
> - Android 15+ also locks the SMS permission for apps installed from a file.

## Part D: set it up

> **App 3.0 (Sajag):** the set-up opens by itself the first time and does steps 2 to 5 below; the buttons are now in Settings (Part M).

1. **Connect your phone to the Pi,** in one of two ways:
   - **The Pi is on a phone's hotspot:** your phone is that hotspot or is connected to it. Use the Pi's address there, for example `https://10.140.209.76:8443`.
   - **The Pi is the hotspot itself** ([network-detector.md](network-detector.md), part 2): join the Wi-Fi `PS3-Guardian-Lab` and use `https://10.42.0.1:8443`. The exception is the phone that gives the Pi internet over USB: it stays off that Wi-Fi, and its app uses the USB address `setup_gateway.sh --keep` prints.
2. **Pi address, token and phone name:** type the address and the pairing token from Part A, and a short **phone name** (for example `A`; every phone gets its own, see Part G). Tap **Save**.
3. **Pair with the Pi** (Part J): tap **Pair with the Pi**, compare the fingerprint the app shows with `cat ~/.ps3_tls_fingerprint` on the Pi, and tap **Trust** only if they are the same. The app then tests the connection: "Connected over HTTPS to the paired Pi. Advisor: llama_service."
4. **The study switch:** **Share message texts with the team's study** is off after installing. Switch it on only if you agreed to the study (Part G, step 4).
5. **Permissions:** tap **Allow SMS and notifications** and allow both.
   - If SMS cannot be allowed or says "restricted setting": go to App info → **⋮** → **Allow restricted settings**.
   - Then go to Permissions → **SMS** → Allow.
6. **Battery:** App info → Battery → **Unrestricted**, so checks still run when the phone is idle.
7. **Test without SMS:** tap **Send a test scam**. A "DANGEROUS" alert appears, and about 30 s later Llama's explanation replaces its text. Tests are not logged on the Pi.
8. **Test with a real SMS:** send yourself an SMS with a link from the Messages app (for example "check this http://example.com"), or ask a friend to send one. Your mobile operator usually answers with an SMS of its own, from a registered sender ID. A line appears in the app's list for each. On the Pi:

   ```bash
   tail -n 2 ~/ps3-guardian/logs/sms_traffic.jsonl
   ```

   A message from a phone number shows `"sender": "mobile"`; business SMS (OTPs, bank alerts, your operator) show their sender ID, for example `"AE-AIRTEL-S"`.

## Part E: collect real traffic and measure

1. **Collect** for about a week. Every incoming SMS, and every chat if you switched chats on (Part F), is checked and logged with the phone's name. The Pi does not have to stay on all the time: see the next point.
   - **Away from the Pi:** an SMS that arrives while the phone cannot reach the Pi is kept on the phone and shows "WAITING for the Pi". It is sent by itself once the Pi can be reached again: within about 15 minutes, or at once when you open the app. Its line then says "checked later". Up to 500 messages are kept, only in the app's private storage, until the Pi has checked them.
   - **Hotspot:** when you come back, the Pi reconnects to your phone's hotspot by itself, as long as the hotspot is on. If your phone switches the hotspot off when nothing is connected, turn that timeout off in the hotspot settings.
   - **Privacy on the Pi:**
     - Texts are kept only for **study phones**, listed in `data/sms/study.json`: phones whose owners agreed. Other phones: time, sender kind and verdicts only. The file was created with the phones already in the log; remove a name to stop keeping that phone's texts.
     - Digits are replaced by `#`.
     - Phone numbers are not stored, nor the names of chat senders.
     - The text of safe messages from phone numbers (mostly personal chats) is not stored, nor the text of any chat that was judged safe.
   - **OTPs:** on Android 17 and later, OTP messages that carry an app code (the 11-character string at the end) reach the app three hours late. Android protects them, and that is fine for this test.
2. **Label it on the Pi.** Each person labels their own phone's messages (the name typed in the app):

   ```bash
   cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
   python scripts/sms_traffic.py label --device B
   ```

   `f` fraud, `m` genuine marketing, `n` normal, Enter if unsure, `u` undo, `q` stop; the screen explains each label, and the app's verdict is not shown. Identical messages are asked once, and labels are saved at once in `data/sms/labels.json`: run it again to carry on. Messages without text (safe messages from phone numbers, safe chats) are not asked. Afterwards, `python scripts/sms_traffic.py review` asks again about likely mistakes (fraud from a registered sender ID, a message labelled two ways).
   - **Or in Excel:** `python scripts/sms_traffic.py export ~/traffic.csv`, copy it to the laptop (PowerShell: `scp arrehinus@10.42.0.1:~/traffic.csv $HOME\Downloads\`), fill the `label` column with `smishing`, `spam` or `ham`, save as **CSV UTF-8**, copy it back (`scp $HOME\Downloads\traffic.csv arrehinus@10.42.0.1:~/`) and run `python scripts/sms_traffic.py import ~/traffic.csv`: the labels go into `data/sms/labels.json`, which model v2 reads.
3. **Measure:**

   ```bash
   python scripts/sms_traffic.py measure
   ```

   It prints flagged messages per label, text only vs with the sender ID, for all messages and then separately for SMS and chats, and how many came from each phone: the real-traffic numbers that replace the projection in `eval/results_sms.md`.
4. **Train SMS model v2** from the labelled messages: [sms-model-v2.md](sms-model-v2.md).
5. **Clean up** only after that: the log and the labels are v2's training data. When the project ends, delete `logs/sms_traffic.jsonl`, `data/sms/labels.json` and `detectors/sms/sms_v2.joblib` on the Pi.

## Part F: chats (RCS and WhatsApp)

Android never passes chat messages to other apps, but it shows them the notifications that chat apps post, if you allow **Notification access**. The app uses that to check chats:

- **Which apps:** Messages (Google Messages and Samsung Messages: RCS chats and MMS) and WhatsApp. Each has its own switch, off until you turn it on.
- **Which senders:** only senders shown as a phone number, that is, people who are not in your contacts, where scam chats come from. Chats from your contacts and from businesses are ignored and never leave the phone, unless you turn on the testing switch.
- **On the Pi:** a chat is scored on its text, plus the same extra weight as an SMS from a phone number when it has a link, money or urgency. Its text is stored only if it was flagged (digits masked), and its sender only as `mobile` (or `name` while testing).
- **Not seen:** chats whose notification you have turned off or muted, and notifications Android hides from apps like this one (on Android 15 and later, notifications that carry an OTP).
- An SMS also shows up as a Messages notification; it is checked once, as an SMS. A notification from a business's sender ID, such as `JD-BOBSMS-S`, is never checked as a chat, not even in testing mode: the SMS check reads its real sender ID.

1. In the app, tick **Check chats in Messages (RCS)** and, if you want, **Check WhatsApp chats**.
2. Tap **Allow notification access**, find **PS3 Guardian** and allow it. Android warns that the app can read notifications: that is what it needs. If the switch is grey or says "restricted setting": App info → **⋮** → **Allow restricted settings**, then try again.
3. Back in the app, the line under the button says which chats are being checked.
4. **Test:** tick **Also check chats from saved contacts (for testing)** and ask a teammate to send you an RCS chat (or a WhatsApp message) with a link, for example `check this http://example.com`. About 5 seconds after it arrives, a line `[Messages] <name> …` appears in the app's list, with an alert if it was flagged. On the Pi, `tail -n 1 ~/ps3-guardian/logs/sms_traffic.jsonl` shows `"channel": "chat"`. Then untick the testing switch.

## Part G: more phones

More phones give more, and more varied, messages: other banks, operators and apps. For each teammate's Android phone (iPhones don't let apps read SMS):

1. **Install** the app the same way: Part C, over USB from Android Studio, never by sending the APK.
2. **Set it up** as in Part D, with the **same Pi address and token**, the **same fingerprint** when pairing, and a **different phone name** (for example `B`, `C`). Part F (chats) is up to them.
3. **Collect:** their messages wait on their phone (up to 500) until it is on the Pi's hotspot, then go to the Pi by themselves.
4. **Agree first:** the Pi keeps sender IDs and verdicts. If they also agree to the study, add their phone name to `data/sms/study.json` on the Pi and they switch on **Share message texts with the team's study** in their app: only with both does the Pi also keep texts, digits masked (business messages, and flagged personal ones); never phone numbers, chat senders' names or the text of safe personal messages. They can leave the study at any time by switching it off on their phone (or by removing the name, or uninstalling the app).

When labelling (Part E), each person labels their own phone's messages (`label --device B`): they know best whether a message really came from their bank.

## Part H: network alerts from the Pi's Wi-Fi

When the phone can reach the Pi, the app also shows what the Pi's network monitor finds on `PS3-Guardian-Lab` ([network-detector.md](network-detector.md)). Every phone with the app sees the alerts for every device on that Wi-Fi, the same list as the Pi's page.

- **Devices, riskiest first** (update 21): each device on the lab Wi-Fi with a risk level from its alerts of the last 24 hours: AT RISK (a dangerous one), CHECK (a suspicious one) or OK. It is fetched only while the app's screen is open.

- **Notifications.** A new alert, dangerous or suspicious, becomes a notification in the channel "Network alerts". If Llama's explanation is not ready yet, the notification shows the playbook's checked text first. When the Pi has Llama's text, the same notification shows it instead, without sounding again.
- **How quickly.** The app asks the Pi about once a minute, and every 10 s while its screen is open. While the phone sleeps, Android delays these checks, by 15 minutes or more. Away from the lab Wi-Fi it tries every 15 minutes.
- **Not flooded.** Alerts older than an hour are only listed, never notified, and at most 3 new notifications come at once.
- **Off switch:** untick **Show network alerts and notify me**. It is on after installing.
- **Data.** The checks go to the Pi over the lab Wi-Fi only. Nothing leaves the lab.

1. **Install** the new version from the Android Studio system: Part B, "Updating the app later", then Part C step 3. On a teammate's phone this is optional.
2. **Check:** with the phone on `PS3-Guardian-Lab` and the Pi address `https://10.42.0.1:8443`, open the app. Under **Network alerts (the Pi's Wi-Fi)** the line says "Checked at …" and the list shows the Pi's alerts. Alerts that are already there are not notified.
3. **Test with the ESP32:** start a test from the Pi's page, for example "Looks up made-up names (DGA)". About 30 s later the alert is on the Pi's page; within a minute it is a notification on the phone, and Llama's text follows in the same notification.
4. **Battery:** App info → Battery → **Unrestricted** (Part D, step 4) keeps the once-a-minute checks regular.

## Part I: files from chats (Share to PS3 Guardian)

The Pi checks files that came in WhatsApp, Messages or an email: what the file really is, hidden code, an app dressed as a document, links to fake websites ([file-checker.md](file-checker.md)).

- **Share to check.** In WhatsApp, long-press the file, then **Share** (the share icon, or **⋮** → **Share**) → **PS3 Guardian: check it**. The app sends the file to the Pi and shows the verdict and the steps, then Llama's explanation. Downloading a file in WhatsApp does not open it, and neither does sharing it. A message's text can be shared the same way.
- **An app sent by a saved contact** gives an alert by itself if chats are switched on (Part F): when a chat notification names an app or program file, such as `Wedding_Invitation.apk`, only that name goes to the Pi, as `Attachment: Wedding_Invitation.apk`. A friend's account that was taken over can send such apps, so this is the one case where a saved contact's chat is checked.
- **Data.** The file goes to the Pi over the lab Wi-Fi only, is checked in memory and is not kept. The Pi's log keeps the file's type, size and verdict, never its name. Files up to 25 MB.

1. **Install** the new version from the Android Studio system: Part B, "Updating the app later", then Part C step 3.
2. **Put the test files on the phone.** On the Pi, `cd ~/ps3-guardian && python3 scripts/make_file_samples.py ~/ps3-file-samples` makes 21 harmless test files. Copy them to the laptop (PowerShell: `scp -r arrehinus@10.42.0.1:~/ps3-file-samples $HOME\Downloads\`), then send a few to yourself in WhatsApp Web (**Message yourself** → attach → **Document**): `ps3-test-ticket.pdf`, `Wedding_Invitation.pdf`, `ps3-test-kyc-link.pdf`, `ps3-test-macro.docm`. On the phone, open that chat and tap the download arrow on each.
3. **Share** `ps3-test-ticket.pdf` to **PS3 Guardian: check it**: "LIKELY SAFE: no danger signs found".
4. **Share** `Wedding_Invitation.pdf`: "DANGEROUS: App or program sent as a file", because "the file says it is .pdf, but it is really an Android app (APK)". Llama's explanation follows, usually within a minute.
5. **The warning for saved contacts** (optional, with chats switched on in Part F): a teammate saved in your contacts sends you `Wedding_Invitation.apk` in WhatsApp as a document. Tell them first that it is a harmless test file. About 5 seconds after the notification, the app shows an alert. On the Pi, `tail -n 1 ~/ps3-guardian/logs/sms_traffic.jsonl` shows `"category": "app_file"`. If nothing comes, look at the notification: if it does not show the file's name, the app cannot see it.

## Part J: HTTPS, pairing and the study switch (update 39)

**Why.** Until update 39 the app talked to the Pi in plain HTTP: anyone on the same Wi-Fi could read the pairing token and the messages on their way (the hard review). Now the phones and the page use HTTPS on port 8443. Port 8000 stays plain HTTP only for the Pi's own scripts (`curl http://127.0.0.1:8000/health`) and for the ESP32's readings, whose token is good for nothing else ([esp32-lab-device.md](esp32-lab-device.md)).

**The certificate.** The Pi makes its own certificate the first time it starts with update 39 (`~/.ps3_tls_cert.pem`, its key in `~/.ps3_tls_key.pem`, readable only by you) and keeps it. No certificate authority vouches for it, so the app pins it instead: it trusts exactly the certificate you confirmed when pairing, and nothing else, not even a valid certificate for another website. Someone else on the Wi-Fi cannot pose as the Pi.

**Pairing, once per phone:**

1. On the Pi: `cat ~/.ps3_tls_fingerprint`. It prints 16 groups of 4 characters, for example `9DAB 8116 9900 …`.
2. In the app: the address `https://10.42.0.1:8443`, the token, **Save**, then **Pair with the Pi**.
3. The app shows the fingerprint of the certificate it received. Compare all 16 groups. Same: tap **Trust**. Different: tap **Cancel**, and do not use that Wi-Fi.

If the Pi ever makes a new certificate (only if its two files are removed), every phone must pair again; the app says so, and keeps its messages until then.

**The page in a browser.** Open `https://10.42.0.1:8443`. The browser warns that the certificate is not trusted, because the Pi made it itself: choose **Advanced** → **Proceed** (Chrome) once per browser. You can compare the fingerprint in the browser's certificate viewer (the padlock or warning icon → certificate → SHA-256 fingerprint). `http://10.42.0.1:8000` now sends the browser to the HTTPS address.

**The study switch.** **Share message texts with the team's study** is the phone owner's own say. Off (after installing): the Pi keeps each message's verdict and sender ID, never its text, even for a phone on the study list. On: the Pi keeps texts as before, if `data/sms/study.json` lists the phone too (Part G, step 4). The owner can switch it off at any time; from then on no text from that phone is kept.

## Part K: Phone Guard, verdicts without the Pi (update 43)

The app now checks every SMS and chat on the phone itself, with the Pi's own rules, model and lists, so a verdict needs no network: at home, on mobile data, or with no network at all. The Pi still adds Llama's explanation and its phishing list when the phone is on its Wi-Fi. How it works, what stays on the Pi and how it was checked: [phone-guard.md](phone-guard.md).

1. **Install:** copy the whole new `android` folder (Part B) and press **Run ▶**. It updates the app in place (version 2.1): settings, pairing and the list stay.
2. Under the title the app says **Phone Guard is on**.
3. **Test:** switch Wi-Fi off and tap **Send a test scam**. The alert comes at once, ending "(Checked on this phone.)"; the list shows "DANGEROUS (…) on this phone, N ms", then "the Pi did not answer". Switch Wi-Fi back on: messages kept meanwhile go to the Pi.

## Part L: Llama on the phone (update 44)

Away from the Pi, the phone's alerts can get Llama's two-sentence explanation too: the app copies the Pi's own Llama 3.2 1B (about 1 GB) once and runs it with ExecuTorch on the phone, with the Pi's prompt and the Pi's checks on the answer. At home the Pi still explains. Details and how it was checked: [phone-guard.md](phone-guard.md#llama-on-the-phone-update-44).

1. **The Pi:** apply update 44 and restart (`sudo systemctl restart ps3-guardian`). It gives its model files only to paired phones, over HTTPS with the token.
2. **The app:** copy the whole new `android` folder (Part B) and press **Run ▶** (version 2.2). The first build downloads ExecuTorch's library from Maven Central, so the Android Studio computer needs the internet once.
3. **Copy Llama:** with the phone on `PS3-Guardian-Lab` and paired (Part J), tap **Get Llama from the Pi (about 1 GB)**, then **Copy**. Keep the screen open (it stays on by itself while copying) for a few minutes. It ends with "Llama 3.2 1B is now on this phone (… MB), checked against the Pi's." Each file is checked against the Pi's SHA-256 before it is used.
4. **Test:** Wi-Fi off, tap **Send a test scam**. The alert comes at once; a few seconds later its text becomes Llama's, ending "(Explained by Llama 3.2 on this phone, in N s.)". The list shows "Llama on this phone explained it in N s, …" with the time to load the model and how many tokens Llama read and wrote, and how fast: note that line for the report. Send a second test scam: the model is still loaded, so that line shows Llama's speed alone.

## Part M: app 3.0, Sajag (update 46)

From version 3.0 the app is called **Sajag** (सजग, Hindi for "alert"). It has four pages, switched by the bar at the bottom, a screen for every alert and a set-up in three steps. The checks themselves are the same as in 2.3: Phone Guard, the Pi (now called the **Home Hub** on screen), Llama on the Pi and on the phone.

1. **Install:** copy the whole new `android` folder over the project on the Android Studio computer (Part B) and press **Run ▶**. It updates the app in place (version 3.0): the pairing, the switches, Llama on the phone and the messages waiting for the Pi stay. A phone that was paired before skips the set-up.
2. **A new phone** opens the set-up by itself: (1) allow SMS and alerts, and notification access for chats if wanted; (2) the Home Hub's address, the pairing code (`cat ~/.ps3_guardian_token` on the Pi) and the phone's name, then **Pair with this Home Hub** and compare the fingerprint as in Part J; (3) copy Llama. Each step can be skipped; **Settings → Run set-up again** opens it later.
3. **Test:** Settings → Advanced → **Send a test scam**. The alert's own screen opens at once: the verdict, what is happening, what to do now (with **Call 1930** and **Report at cybercrime.gov.in**), why it was flagged and the message with its link broken. It fills in by itself when the Home Hub answers and when Llama's explanation is ready. The notification has two buttons: **What to do** (that screen) and **Call 1930** (the dialler, with the number filled in; nothing is called by itself).

| In app 2.x | In Sajag 3.0 |
| --- | --- |
| The list of results | **Alerts** (all, scams or safe, by day; each opens its own screen). Home shows the newest three |
| The lines with timings ("on this phone, N ms", "Llama on this phone explained it in …") | Each alert's screen, at the bottom; all of them in **Settings → Advanced → Activity log** |
| Pi address, token, phone name, **Save** | Set-up step 2, or **Settings → Advanced** (Home Hub address, Pairing code, Phone name): each saves at once |
| **Pair with the Pi**, **Test connection** | **Settings → Home Hub** (**Pair again**, **Test connection**) |
| **Get Llama from the Pi** | **Settings → Explanations → Add from your Home Hub** (or **Update…** once it is there), or set-up step 3 |
| **Allow SMS and notifications**, **Allow notification access** | Set-up step 1, or **Settings → What to check** |
| Chat switches, **Show network alerts and notify me** | **Settings → What to check** (and a new switch to pause SMS checks) |
| **Share message texts with the team's study** | **Settings → Privacy → Help improve detection** (same switch, still off until switched on) |
| **Also check chats from saved contacts**, **Send a test scam** | **Settings → Advanced** |
| Network alerts and devices | **Network**: a summary card, the devices riskiest first (tap one for its details or its newest alert), then the alerts (each opens its own screen) |
| Share to **PS3 Guardian: check it** | Share to **Check with Sajag**: the result opens on the alert's own screen |
| — | **Home → Check a message** and **Check a link**: paste a text or a link to check it the same way |

The look: charcoal and ivory, with red, yellow and green used only for verdicts (always with an icon and a word); the Figtree font, and the name सजग in Rozha One. Both fonts are under the SIL Open Font License; their licence texts are in `app/src/main/assets/licenses/`.

## If something goes wrong

| What you see | Fix |
| --- | --- |
| "Can't reach your Home Hub" (app 3.0) or "Cannot reach the Pi" | Same hotspot? On the Pi, `curl -s http://127.0.0.1:8000/health` must print `{"ok":true,...}`; if not, `systemctl status ps3-guardian --no-pager` and `tail -n 30 logs/app.log`. The Pi's address is in `hostname -I`. |
| `HTTP 401`, or Home Hub "Code not accepted" | The token is wrong or old (it changed in update 36): `cat ~/.ps3_guardian_token` on the Pi, then type it in Settings → Advanced → **Pairing code** |
| "not paired with the Home Hub yet" (or "… the Pi yet") | Settings → Home Hub → **Pair again** (Part J). |
| "the Pi's certificate is not the one this phone paired with" | The Pi made a new certificate (its files `~/.ps3_tls_cert.pem` or `~/.ps3_tls_key.pem` were removed), or this is not your Pi. Compare again: Settings → Home Hub → **Pair again**, and trust it only if the fingerprint matches `cat ~/.ps3_tls_fingerprint`. Messages wait on the phone meanwhile. |
| "The app talks to the Pi only over HTTPS" | The address must start with `https://` and end with `:8443`. |
| `HTTP 403` with "use https://…" | Something talked plain HTTP to port 8000 from another machine: since update 39 that port takes only the ESP32's readings. Use `https://<Pi>:8443`. |
| `HTTP 429` | Ten wrong tokens in a minute from this phone: wait a minute, then type the right one |
| `HTTP 503` | The Pi has no token: `sudo systemctl restart ps3-guardian` |
| "Your Home Hub was out of reach" (app 3.0) or "WAITING for the Pi" | Normal while the phone cannot reach the Pi: the phone has already judged the message (the line above it), Llama on the phone explains it if it was copied there (Part L), and the phone sends it to the Pi later for the phishing list and the Pi's own explanation. Many of them: check the Pi as for "Cannot reach the Pi". |
| "Checks on this phone could not start" (or "Phone Guard could not start") | The app was built without its `assets/guard` folder: copy the whole `android` folder again (Part B) and **Run ▶**. Until then messages wait for the Pi, as before update 43. |
| "The Pi has no Llama files to give" | "it runs an older version": apply update 44 on the Pi and `sudo systemctl restart ps3-guardian`. Otherwise its model files are not where `scripts/run_pi.sh` looks: on the Pi, `ls -l ~/executorch-deployment/llama3_2.pte ~/executorch-deployment/tokenizer.model`, then restart. |
| "The copy stopped: …" | The phone left the Pi's Wi-Fi or the screen was closed. Tap **Add from your Home Hub** again (Settings → Explanations): it goes on from where it stopped. |
| "not enough free space on the phone" | Llama needs about 1.2 GB free: delete some photos or videos, then try again. |
| "Llama on this phone could not answer: …" | Send that line. The alert keeps the playbook's advice meanwhile. |
| "Llama on this phone (N s): answer not used, …" | Normal now and then: Llama's answer failed the Pi's checks, so the playbook's advice stays, as on the Pi. |
| A message came with the Wi-Fi off, but no Llama explanation | Only flagged messages are explained. If Alerts shows it as **Safe**, there was no alert and nothing to explain, as on the Pi. To test, send a scam-like text from another phone; for WhatsApp, a new text each time (the app skips a chat text it has checked in the last 2 days). |
| Build error "Could not resolve org.pytorch:executorch-android:1.5.1" | The Android Studio computer needs the internet for the first build after update 44 (Maven Central). |
| Build error "2 files found with path 'lib/arm64-v8a/…'" | Send the first error line: that library's name goes into `pickFirsts` in `app/build.gradle.kts`, next to `libc++_shared.so`. |
| No alert, but the list shows the message | It was judged safe (no alert for safe messages), or notifications are off for the app |
| Nothing at all when an SMS arrives | SMS permission (Part D, step 5), **Text messages (SMS)** on in Settings, and battery Unrestricted (step 6). Chats are checked only as set up in Part F. |
| Network alerts: "Cannot reach the Pi" | The phone must be on `PS3-Guardian-Lab`, with the Pi address `https://10.42.0.1:8443`, paired (Part J). |
| No notification for a network alert | Is **Home network alerts** on in Settings, and are notifications on for "Network alerts" (App info → Notifications)? Only alerts newer than an hour, seen for the first time, are notified. |
| A chat is not checked | Is its switch on in Settings, and does **Notification access for chats** say Allowed? Is the sender shown as a phone number (not in your contacts)? Are notifications on for that chat? The check runs about 5 seconds after the notification. |
| No **Check with Sajag** (or **PS3 Guardian: check it**) when sharing | Install the update 29 version (Part I, step 1). In the share list, scroll or tap **More**. |
| After sharing: "Could not read the file" | The file is not on the phone yet: in WhatsApp, tap the download arrow first, then share again. |
| After sharing: "Could not reach the Pi" | As for the network alerts: the phone must be on `PS3-Guardian-Lab`, with the Pi address `https://10.42.0.1:8443`, paired (Part J). |
| After sharing: `HTTP 404` | The Pi runs an older version: apply update 29 and `sudo systemctl restart ps3-guardian`. |
| After sharing: "Too big to check" | The Pi checks files up to 25 MB. |
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

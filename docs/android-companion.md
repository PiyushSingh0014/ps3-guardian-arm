# Android companion: read incoming SMS with their sender IDs

## Why

On the India test set, the sender ID decides most false alarms:

- **Text only:** 64% of normal messages are flagged.
- **With the real registered sender ID** (projected): about 4%.

Typed names don't work, so the app must read the ID itself. An Android app gets the raw ID with every SMS:

- `JD-HDFCBK-S` for a business
- `+919812345678` for a phone number

```
incoming SMS ──> Android app ──(Wi-Fi hotspot, POST /sms + pairing token)──> Pi
                    ▲                                                     │ detector + sender scoring
                    └──────────── verdict + advice (alert) ◄──────────────┤ Llama explanation (later)
                                                                          └─> logs/sms_traffic.jsonl
```

## Part A: update the Pi (update 5)

1. Copy the bundle from the laptop to the Pi. In **PowerShell** (`PS C:\Users\Lenovo>`):

   ```powershell
   scp $HOME\Downloads\ps3-guardian-update5.bundle arrehinus@10.140.209.76:~/
   ```

2. On the Pi (`arrehinus@ps3-guardian`), pull it, push it to GitHub and restart the app:

   ```bash
   cd ~/ps3-guardian
   git pull --no-rebase ~/ps3-guardian-update5.bundle step3
   git push
   pkill -f "uvicorn app.server" ; sleep 1
   nohup bash scripts/run_pi.sh > logs/app.log 2>&1 &
   sleep 5; grep -E "App:|pairing token" logs/app.log
   ```

3. Note the two values it prints:
   - the Pi address, for example `http://10.140.209.76:8000`
   - the pairing token, 8 characters. It is created once and kept in `~/.ps3_guardian_token`.

## Part B: build the app (laptop)

1. **Install Android Studio** (the current stable version) from developer.android.com/studio.

2. **New Project → Empty Views Activity:**

   | Field | Value |
   | --- | --- |
   | Name | `PS3 Guardian` |
   | Package name | `com.ps3guardian.companion` |
   | Language | Kotlin |
   | Minimum SDK | API 26 |
   | Build configuration language | Kotlin DSL |

3. **Edit `app/build.gradle.kts`** (the one in the `app` folder):
   - Inside `defaultConfig`, find the `targetSdk` line and change its number to **36**, for example `targetSdk = 36`. Leave `compileSdk` as it is.
   - In `dependencies`, add:

     ```kotlin
     implementation("androidx.work:work-runtime-ktx:2.10.1")
     ```

   Keep the target at 36 even if Android Studio suggests 37: apps targeting Android 17 (API 37) receive OTP-like SMS three hours late and need an extra local-network permission. Click **Sync Now**. If Android Studio offers a newer WorkManager version, accept it.

4. **Copy the files** from this repo's `android/app/src/main/` into the project's `app/src/main/`:

   | From the repo | Into the project | |
   | --- | --- | --- |
   | `AndroidManifest.xml` | `app/src/main/AndroidManifest.xml` | replace; keep your template's `android:theme` value if it is not `Theme.PS3Guardian` |
   | `java/com/ps3guardian/companion/*.kt` (7 files) | `app/src/main/java/com/ps3guardian/companion/` | replace `MainActivity.kt`, add the others |
   | `res/layout/activity_main.xml` | `app/src/main/res/layout/` | replace |
   | `res/xml/network_security_config.xml` | `app/src/main/res/xml/` | create the `xml` folder |

5. **Build → Make Project.** It should finish without errors. If it doesn't, send the first error line.

## Part C: install it on your phone

1. **Developer options:** Settings → About phone → Software information → tap **Build number** 7 times. Then Settings → Developer options → turn on **USB debugging**.
2. **Samsung only:** Settings → Security and privacy → **Auto Blocker** → off while you install (it blocks commands over USB). Turn it back on afterwards; the installed app keeps working.
3. **Install:** connect the phone by USB, tap **Allow** on the "USB debugging" prompt, pick the phone in Android Studio and press **Run ▶**. If Play Protect asks, choose to install anyway: it is your own app.

> Install it only this way. Don't send the APK through WhatsApp, Drive or a browser:
> - In India, Play Protect blocks apps installed that way when they ask for SMS permissions.
> - Android 15+ also locks the SMS permission for apps installed from a file.

## Part D: set it up

1. **Connect your phone to the Pi.** The phone must be the hotspot the Pi is on, or connected to the same hotspot.
2. **Pi address and token:** type the address and the pairing token from Part A, tap **Save**, then **Test connection**. You should see "Connected. Advisor: …".
3. **Permissions:** tap **Allow SMS and notifications** and allow both.
   - If SMS cannot be allowed or says "restricted setting": go to App info → **⋮** → **Allow restricted settings**.
   - Then go to Permissions → **SMS** → Allow.
4. **Battery:** App info → Battery → **Unrestricted**, so checks still run when the phone is idle.
5. **Test without SMS:** tap **Send a test scam**. A "SUSPICIOUS"/"DANGEROUS" alert appears, and about 30 s later Llama's explanation replaces its text. Tests are not logged on the Pi.
6. **Test with a real SMS:** from a friend's phone, send yourself a message with a link (for example "check this http://example.com"). An alert or a "SAFE" line should appear in the app's list. On the Pi:

   ```bash
   tail -n 2 ~/ps3-guardian/logs/sms_traffic.jsonl
   ```

   The line shows `"sender": "mobile"`. Business SMS (OTPs, bank alerts) show their sender ID, for example `"JD-HDFCBK-S"`.

## Part E: collect real traffic and measure

1. **Collect:** keep the Pi running and your phone on its hotspot for about a week. Every incoming SMS is checked and logged.
   - **Privacy:**
     - Digits are replaced by `#`.
     - Phone numbers are not stored.
     - The text of safe messages from phone numbers (mostly personal chats) is not stored.
   - **OTPs:** OTP messages that carry an app code (the 11-character string at the end) reach the app three hours late, or not at all. Android protects them, and that is fine for this test.
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
4. **Measure.** Copy it back and run:

   ```powershell
   scp $HOME\Downloads\traffic.csv arrehinus@10.140.209.76:~/traffic.csv
   ```

   ```bash
   python scripts/sms_traffic.py measure ~/traffic.csv
   ```

   It prints flagged messages per label, text only vs with the sender ID: the real-traffic numbers that replace the projection in `eval/results_sms.md`.
5. **Clean up:** after measuring, delete the log on the Pi with `rm ~/ps3-guardian/logs/sms_traffic.jsonl`.

## If something goes wrong

| What you see | Fix |
| --- | --- |
| "Cannot reach the Pi" | Same hotspot? The Pi's address may have changed: check `grep App: logs/app.log` on the Pi. Is the app running? |
| `HTTP 401` | The token is wrong: `cat ~/.ps3_guardian_token` on the Pi |
| `HTTP 503` | The Pi has no token: restart it with `scripts/run_pi.sh` |
| No alert, but the list shows the message | It was judged safe (no alert for safe messages), or notifications are off for the app |
| Nothing at all when an SMS arrives | SMS permission (Part D, step 3) and battery Unrestricted (step 4) |
| Build error in Android Studio | Send the first error line |

## Sources for the Android rules above

- Play Protect in India blocks sideloaded apps that request SMS permissions: [9to5Google, Oct 2024](https://9to5google.com/2024/10/03/google-blocking-sideloaded-apps-india/).
- Android 15 restricts the SMS permission for apps installed from a file: [Android Authority](https://androidauthority.com/android-15-restricted-settings-sideloading-3481098); how to allow it: [textbee.dev](https://textbee.dev/blog/android-15-send-sms-permission-guide).
- OTP SMS delays: [Android 17 behaviour changes](https://developer.android.com/about/versions/17/behavior-changes-all).
- Local network permission for apps targeting Android 17: [Android developers](https://developer.android.com/privacy-and-security/local-network-permission).
- Samsung Auto Blocker: [Samsung support](https://www.samsung.com/sg/support/mobile-devices/protect-your-galaxy-device-with-the-new-auto-blocker-feature).

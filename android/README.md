# PS3 Guardian Android companion

A small Android app that reads every incoming SMS **with its sender ID** (for example `JD-HDFCBK-S`, or a phone number), sends both to the Pi (`POST /sms`), and shows a scam alert when the Pi flags the message. The Pi logs each message so the detector can be measured on real traffic.

These are the source files only. Create a project with Android Studio's *Empty Views Activity* template and copy them in: the template provides the Gradle files for your Android Studio version. Step-by-step instructions: [`docs/android-companion.md`](../docs/android-companion.md).

| File | What it does |
| --- | --- |
| `AndroidManifest.xml` | Permissions (receive SMS, internet, notifications) and the SMS receiver |
| `SmsReceiver.kt` | Called by Android for every SMS: joins the parts of long messages, takes the raw sender ID |
| `Checker.kt` | Sends the SMS to the Pi, keeps a list of recent results, shows the alert |
| `PiClient.kt` | The HTTP calls: `/health`, `/sms` (with the pairing token), `/explain/{id}` |
| `ExplainWorker.kt` | Background job: waits for Llama's explanation on the Pi and updates the alert |
| `Notifier.kt` | The alert notification |
| `Settings.kt` | The Pi address, the pairing token, the recent results |
| `MainActivity.kt`, `activity_main.xml` | One screen: address, token, permissions, two tests, recent results |
| `network_security_config.xml` | Allows plain HTTP, which the Pi uses on the hotspot |

The app never sends, deletes or changes SMS, and it talks only to the Pi.

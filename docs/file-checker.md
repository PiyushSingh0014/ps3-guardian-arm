# File checker: is a file from a chat dangerous? (`detectors/files`)

A file that came in WhatsApp, Messages or an email can be checked on the Pi: a PDF, a Word, Excel or PowerPoint file, an app (APK), a zip, or a web page saved as a file. The Pi answers **safe**, **suspicious** or **dangerous**, with reasons and steps like for a message, and Llama explains suspicious and dangerous files. The file is checked in memory and never stored.

Results on the test files: [eval/results_files.md](../eval/results_files.md).

## Why

Scams in India send files as well as links. Police, I4C and banks keep warning about the same few tricks:

- **An app sent as a file:** a "wedding invitation", an "RTO challan" or a "salary calculator" that is really an Android app (APK). Once installed, it reads the SMS (OTPs) and can take over the phone. It can come from a friend's number too, when their phone or WhatsApp account has been taken over.
- **An app dressed as a document:** `Invitation.pdf.apk`, or an app simply renamed `Invitation.pdf`.
- **A document that leads to a fake website:** a "KYC" letter or a bill with a link to a fake bank page.
- **A document with hidden code:** a PDF with JavaScript or a launch action, an Office file with macros, a template loaded from the internet, or DDE.

## Privacy: what the Pi looks at, and what it never does

- **Only when you ask.** The phone sends a file only when you share it to PS3 Guardian, and the page only when you pick one. The app never reads WhatsApp's folders.
- **To the Pi only.** The file goes over the lab Wi-Fi to the Pi: no cloud, no antivirus service, no web look-ups. Links are checked against the lists already on the Pi.
- **In memory, never stored.** The file is dropped when the answer is sent. The log (`logs/file_checks.jsonl`) keeps one line per check: time, file type, size in KB, verdict, category, and `via` (`file` from the page, `share` from the phone). Never the name, never anything from inside.
- **Structure, not content.** The checker looks for the parts a harmful file needs: code, launch commands, macros, an app's permissions, links. It does not read what the person wrote.
- **Llama sees only the reasons.** Reasons never contain the file's name or a link, because the sender chose both. Llama gets the reasons and the playbook, never the file.
- **The app-file warning for chats** sends only the file's name (`Attachment: Wedding_Invitation.apk`), never the message or the contact's name.

## What it checks

First, **what the file really is**, from its first bytes: the name does not count. Then the signs for that type.

| The file really is | Signs looked for |
| --- | --- |
| Any file | Its real type against the ending of its name: an app or program named `.pdf` or `.jpg`; a double ending (`Card.pdf.apk`); a hidden right-to-left character that turns the ending around (`invoice<RLO>fdp.apk` shows as `invoicekpa.pdf`) |
| Android app (APK) | Dangerous whenever it comes in a chat. The permissions in its manifest are named when OTP and money thieves need them: read SMS, control the screen (accessibility), read notifications, read contacts, draw over other apps, install other apps |
| Windows, Linux or Java program, or a script | Dangerous |
| PDF | The signs [pdfid](https://blog.didierstevens.com/programs/pdf-tools/) counts: JavaScript, and whether it runs by itself on opening (the OpenAction, a page's "opened" action, a document script that does more than define functions), `/Launch`, `/RichMedia`, `/SubmitForm`, `/GoToE`, `/GoToR`. Read from the PDF's dictionaries, also inside object streams and behind `#xx`-escaped names such as `/J#61vaScript`. Scripts that cannot do harm do not count (below). Files inside the PDF are checked like files of their own. Its links |
| Word, Excel, PowerPoint (`.docx`, `.xlsx`, `.pptx`, and macro versions) | Macros, a template or object loaded from the internet, DDE fields, a program inside an embedded object. Its links |
| Old Office file (`.doc`, `.xls`) | Macros |
| OpenDocument (`.odt`, `.ods`) | Macros. Its links |
| Zip | Locked with a password; an app or program inside; up to 20 documents, apps or web pages inside, checked like files (one level deep) |
| RAR, 7-Zip | The Pi cannot open them: suspicious |
| Web page or SVG saved as a file | A password box (a fake sign-in page that needs no website), code that sends you elsewhere, scripts, forms. Its links |
| Text file | Its links |
| Photo, video or audio | Safe when that is really what it is |

- **Only the PDF's dictionaries count** (update 30). Pictures, fonts and page text are stream data, and random bytes contain `/JS` or `/AA` about 0.06 times per MB each. Read as keys, they made everyday PDFs look as if they had JavaScript ([eval/results_files.md](../eval/results_files.md)).
- **Scripts that cannot do harm** (update 31): Acrobat's own form helpers with fixed values (`AFNumber_Format(2, 0, 0, 0, "", true);`), page jumps (`this.zoom=100;this.pageNum=162`, as e-books use for their contents), and KiCad's schematic menus, which show a part's details and datasheet links when you click it. KiCad's menu function is recognised by a fingerprint of its text, one per KiCad version (8 and 9, and 10), so a changed function counts as code again. Web addresses inside scripts go to the link checker.
- **Links.** Up to 20 different websites per file go through the link checker ([url-detector.md](url-detector.md)). A dangerous link makes the file dangerous, a suspicious one suspicious. A dangerous website also goes on the Pi's watch list, so the network monitor can tell if a device on the lab Wi-Fi opens it. E-mail and phone links (`mailto:`, `tel:`) are not websites and are skipped.
- **Verdict.** The strongest sign decides, with the thresholds of SMS and links: a score of 0.5 or more is suspicious, 0.8 or more dangerous. At most 4 reasons are shown.
- **Only suspicious** for signs that ordinary files also have: JavaScript that runs only when you type or click, a form that sends what you type, a file inside a PDF that the Pi cannot read or does not know, a link to another file, a password-locked zip, RAR and 7-Zip.
- **Protection for the Pi itself.** Files up to 25 MB; at most 50 MB unpacked per file (against zip bombs); at most 400 object streams, 200 scripts and 20 files inside one PDF, and 2,000 zip entries. The checker reads bytes only: it never opens the file in a reader, never runs it and never unpacks it to disk.

| Sign | Score |
| --- | --- |
| An app or program named like a document or photo; a zip holding an app or program | 0.98 |
| An APK | 0.97 |
| An APK asking for SMS, screen control and similar permissions | 0.96 |
| A double ending or a hidden right-to-left character; a PDF that can launch a program or hides an app; a template from the internet; a program inside an Office object; a file named as an app or program | 0.95 |
| JavaScript that runs by itself when the PDF opens; macros; an object from the internet; DDE; a web page with a password box; a dangerous link | 0.9 |
| A `.pdf`, document or photo that is really a web page or an archive | 0.85 |
| An SVG picture with code | 0.8 |
| A web page with code that sends you elsewhere | 0.75 |
| Other JavaScript in a PDF, or a script that cannot be read | 0.65 |
| A password-locked zip; a file inside a PDF that cannot be read or is of an unknown type; embedded media; a web page with a script or a form; a suspicious link | 0.6 |
| A PDF form that sends what you type | 0.55 |
| A PDF that opens another file; a RAR or 7-Zip archive; a damaged zip | 0.5 |
| A file inside a zip or a PDF | its own score, reason starting "inside the zip:" or "inside the PDF:" |

## Use it

### On the Pi's page

1. On a laptop or phone on `PS3-Guardian-Lab`, open https://10.42.0.1:8443 (since update 39; the browser warns once about the Pi's own certificate: [android-companion.md](android-companion.md), Part J).
2. Under the message box, choose the file and press **Check a file**.
3. The answer shows the verdict, the file's real type and size, the reasons and the steps. For a suspicious or dangerous file, Llama's explanation follows.

### On the phone: Share to PS3 Guardian

In WhatsApp, long-press the file, then **Share** (the share icon, or **⋮** → **Share**) → **PS3 Guardian: check it**. Files, Gmail and Messages share the same way. Downloading a file in WhatsApp does not open it, and neither does sharing it. You can share a message's text too. Setup and a test: [android-companion.md](android-companion.md), Part I.

### By itself: an app sent by a saved contact

If chats are switched on in the app ([android-companion.md](android-companion.md), Part F), a chat notification that names an app or program file (`.apk`, `.apks`, `.xapk`, `.apkm`, `.exe`, `.scr`, `.msi`, `.bat`) raises an alert, even from a saved contact: a friend's account that was taken over can send such apps too. Only the file's name goes to the Pi, and only if the chat app's notification shows it. The Pi also flags such a name in any message checked on the page or as an SMS.

### From a script

On the Pi itself (plain HTTP from the Pi needs no token):

```bash
curl -s --data-binary @Invitation.pdf -H "Content-Type: application/octet-stream" \
     "http://127.0.0.1:8000/file?name=Invitation.pdf&language=en"
```

From another machine, use HTTPS and the pairing token: `curl -s --cacert pi-cert.pem -H "X-Guardian-Token: $TOKEN" ... "https://10.42.0.1:8443/file?..."`, where `pi-cert.pem` is a copy of the Pi's `~/.ps3_tls_cert.pem` (the certificate names the address `10.42.0.1`).

`POST /file` takes the file as the raw request body; `name` (for its ending), `language` (`en` or `hi`) and `channel` (written to the log as `via`) are optional. It answers like `POST /check`. A file over 25 MB gets HTTP 413, an empty one 422. On Windows PowerShell, write `curl.exe`.

### On many files at once: count false alarms

```bash
cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
python scripts/check_files.py ~/normal-files --quiet
```

It checks every file in the folder on this machine and prints the flagged ones (without `--quiet`, all of them), then a table per file type and the time per file. Copies of the same file (`- Copy.pdf`) are counted once. `--details` adds what was found inside each listed file: for a PDF, its keys and the start of a script. File names are shown only on your screen; nothing is logged.

## Test files

```bash
cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
python scripts/make_file_samples.py ~/ps3-file-samples
python scripts/check_files.py ~/ps3-file-samples
```

21 harmless files made for this project. 15 carry the signs of harmful files and nothing else: the "apps" have a made-up manifest and no code, so Android refuses to install them; the "JavaScript" only shows a message box; the "launch" names a program that does not exist; the "macro" is a placeholder without code; the links and the template point to made-up websites; the sign-in page sends nowhere. 6 are safe, two of them hard cases: a form whose fields use Acrobat's number helpers, and a scanned page whose picture bytes happen to contain `/JS (` and `/AA <<`. The list is in [eval/results_files.md](../eval/results_files.md).

## Limits

- **"Safe" means no danger sign was found,** not that the file is safe. A PDF that attacks a bug in one reader, with none of these signs, would pass. So would a scam letter with only a phone number to call: the checker does not read the text for meaning.
- **Not checked:** QR codes and text inside pictures or scanned pages, links written as plain text in a PDF or Office file (only real, clickable links are read), RAR and 7-Zip archives, and zips inside zips.
- **Encrypted PDFs and zips:** only their outside is read, and the answer says so. In an encrypted PDF the keys outside object streams still count, but its links and scripts are scrambled. Many bank statements are encrypted, so encryption alone is no warning.
- **Not an antivirus.** It has no list of known harmful files and does not run anything.
- **Sent as plain HTTP on the lab Wi-Fi,** like the messages from the app: someone who has the Wi-Fi password and records the traffic could read the file. Check private documents only on a Wi-Fi you trust.
- **False alarms on everyday documents are not measured yet.** Tool: `scripts/check_files.py` (above).

## Code

| File | What |
| --- | --- |
| `detectors/files/names.py` | File endings for apps, programs, documents; name tricks; an app file named in a chat message |
| `detectors/files/checker.py` | The real type of a file and its signs: `FileChecker.check(data, name)` returns a `Finding` (`source="file"`) |
| `advisor/playbooks/app_file.md`, `harmful_document.md`, `phishing_document.md` | What to do, for the advice and for Llama's prompt |
| `app/server.py` | `POST /file`, and the file picker on the page |
| `android/.../ShareActivity.kt` | Share to PS3 Guardian: sends the file or text to the Pi, shows the answer and Llama's text |
| `android/.../ChatListener.kt`, `ChatApps.kt` | The app-file warning for chats from saved contacts |
| `scripts/make_file_samples.py`, `scripts/check_files.py` | Harmless test files; check a folder |
| `tests/test_files.py` | Tests |

## Sources

- Fake wedding invitations as apps: [Maharashtra Cyber Police](https://www.freepressjournal.in/mumbai/maharashtra-cyber-police-warn-citizens-of-wedding-invitation-scam-leading-to-malware-financial-losses-check-details) (Free Press Journal), [Rajasthan Police](https://theprint.in/india/rajasthan-police-warns-against-scams-through-wedding-invites-on-whatsapp/2914411/) (ThePrint), [The Quint](https://www.thequint.com/news/webqoof/scammers-send-fake-wedding-invitations-on-whatsapp-with-apk-files-that-are-malware).
- Banks: [UCO Bank, "Beware of APK files"](https://ucobank.com/documents/d/guest/security-advisory-beware-of-apk-files).
- I4C on harmful APK files sent on WhatsApp to government employees: [India TV, February 2026](https://www.indiatvnews.com/technology/news/8th-pay-commission-whatsapp-scam-i4c-warns-government-employees-against-malicious-apk-files-2026-02-14-1030266). Fake RTO challan apps on SMS and WhatsApp: [Greater Kashmir](https://m.greaterkashmir.com/article/crime-branch-warns-public-against-fake-rto-challan-apk-scam-circulating-via-sms-whatsapp/462710).
- PDF signs: Didier Stevens' [pdfid](https://blog.didierstevens.com/programs/pdf-tools/). Office macros: [oletools](https://github.com/decalage2/oletools).
- MITRE ATT&CK: [right-to-left override](https://attack.mitre.org/techniques/T1036/002/), [double file extension](https://attack.mitre.org/techniques/T1036/007/), [template injection](https://attack.mitre.org/techniques/T1221/), [DDE](https://attack.mitre.org/techniques/T1559/002/).

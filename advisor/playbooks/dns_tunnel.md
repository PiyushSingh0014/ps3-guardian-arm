# Data hidden in DNS lookups
severity: critical
summary: A device made many long, never-repeating lookups under one website. Malware uses DNS like this to sneak data out or to take orders past security checks.
pretends: a program on one of your devices
wants: to smuggle your data out, or control the device, without being noticed
fact: Normal lookups are short and repeat; hundreds of long unique names under one website carry hidden data.

## Steps
1. Disconnect the device from the Wi-Fi.
2. Run a full security scan, or reset an IoT device to factory settings.
3. From a different, clean device, change the passwords of accounts used on the affected one.

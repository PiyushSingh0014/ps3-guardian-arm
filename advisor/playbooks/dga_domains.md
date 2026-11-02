# Malware looking for its controller (random website names)
severity: critical
summary: A device looked up many random-looking website names in a few minutes. Malware does this to find its controller's current address.
pretends: a program on one of your devices
wants: to reach its controller and take orders, or send out your data
fact: People and apps look up the names of real websites; bursts of made-up names (long strings of random letters) come from malware that keeps making up new names to find its controller.

## Steps
1. Disconnect the device from the Wi-Fi.
2. Run a full security scan; if it is an IoT device or the scan finds nothing, reset it to factory settings.
3. From a different, clean device, change the passwords of accounts used on the infected one.

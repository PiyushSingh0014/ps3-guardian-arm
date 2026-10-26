# Port scan on your network
severity: high
summary: A device is trying many ports on another device, one after another. Attackers do this to find a way in, and infected devices do it to spread.
pretends: a device on your Wi-Fi
wants: to find an open door into your devices
fact: Normal phones, laptops and sensors connect to a few ports on a few servers; trying dozens of ports on one device in a minute is what scanning tools do.

## Steps
1. Find the device in the alert (its name or address). If you do not recognise it, change the Wi-Fi password so it is thrown off.
2. If it is your own device, disconnect it from the Wi-Fi, update it, and reset it to factory settings if the alert repeats.
3. Turn off remote-login services you do not use (Telnet, SSH, remote desktop) on your devices.

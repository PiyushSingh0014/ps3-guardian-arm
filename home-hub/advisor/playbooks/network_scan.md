# Device scanning other machines (worm or botnet)
severity: critical
summary: A device is trying to reach many machines on the same port. Infected cameras, routers and other IoT devices do this to spread malware.
pretends: an infected device on your Wi-Fi
wants: to take over more devices and add them to a botnet
fact: Infected devices spread by trying one service on many machines in a row, looking for weak passwords or known flaws; normal devices connect to a few servers, and those answer.

## Steps
1. Unplug the device or remove it from the Wi-Fi now.
2. Reset it to factory settings, update its software, and change its default password before you connect it again.
3. Check the other devices on your network for the same alert.

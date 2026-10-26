# Device scanning other machines (worm or botnet)
severity: critical
summary: A device is trying to reach many machines on the same port. Infected cameras, routers and other IoT devices do this to spread malware.
pretends: an infected device on your Wi-Fi
wants: to take over more devices and add them to a botnet
fact: Mirai-type botnets infect cameras and routers with default passwords and then scan the internet for more of them on Telnet.

## Steps
1. Unplug the device or remove it from the Wi-Fi now.
2. Reset it to factory settings, update its software, and change its default password before you connect it again.
3. Check the other devices on your network for the same alert.

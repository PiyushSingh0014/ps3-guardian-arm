# Connection on a port malware uses
severity: medium
summary: A device connected to the internet on a port home devices never use, such as Telnet or IRC. Malware uses these to spread or to take orders.
pretends: a program on one of your devices
wants: to spread malware or take orders from its controller
fact: Home apps and sensors reach the internet on a few common ports; ports such as Telnet, IRC and Windows file sharing are rarely needed there and are often used by malware to spread or take orders.

## Steps
1. Find the device in the alert and check which apps or services it runs.
2. If it is an IoT device, update it and change its default password; reset it if the alert repeats.
3. Uninstall apps you do not recognise, and run a security scan on phones and computers.

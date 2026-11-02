# Advisor review (network alerts, fresh)

Source: 10 samples + `logs/net_alerts.jsonl`. 12 alerts, 12 flagged, 11 distinct prompts.

| # | Category | Alerts | Prompt tok (reused) | TTFT s | Decode tok/s | Total s | Valid | Explanation |
|---|---|---|---|---|---|---|---|---|
| 1 | port_scan | 1 | 692 (0) | 52.217 | 3.062 | 67.567 | yes | A device on your Wi-Fi tried 100 different ports on another device in a few seconds, looking for an open door into your devices. This is how attackers look for a way in, as most ports are closed by normal devices. |
| 2 | network_scan | 1 | 710 (640) | 5.578 | 3.078 | 23.447 | yes | A device on your Wi-Fi scanned 23 different machines on Telnet within a minute, trying to connect to weak passwords or known flaws, which is how malware spreads and takes over more devices. This is how Mirai-type botnets infect devices from infected cameras and routers. |
| 3 | dos_flood | 1 | 690 (576) | 8.845 | 3.078 | 21.84 | yes | A device on your Wi-Fi sent a large number of half-open connection requests (SYN flood) to another device on port 80, which is a common attack to overload a server or device. |
| 4 | brute_force | 1 | 677 (576) | 8.049 | 3.098 | 21.281 | yes | A device on your Wi-Fi made 40 quick login attempts on SSH (Secure Shell) to another device on your network within a minute, which is how password-guessing tools try to guess passwords. |
| 5 | risky_port | 1 | 681 (576) | 8.414 | 3.075 | 23.046 | yes | A device on your Wi-Fi connected to an internet address on IRC chat, which is used to control bots, and is not used by home devices. This is a possible sign of malware or a botnet controlling a device. |
| 6 | malware_beacon | 2 | 691 (576) | 9.164 | 3.082 | 24.09 | yes | A device on your Wi-Fi contacts a website every 60 seconds, which is how malware keeps control of a device and waits for orders. This is a rhythm to an unknown server, which is a warning sign, not proof. |
| 7 | phishing_lookup | 1 | 690 (576) | 8.895 | 3.089 | 24.11 | yes | A device on your Wi-Fi opened a fake website that uses SBI's name to steal a password, card details or OTP. Real Indian bank websites end in .bank.in, and this address is not SBI's official website. |
| 8 | dga_domains | 1 | 701 (576) | 9.657 | 3.098 | 20.633 | yes | A device on your Wi-Fi looked up 5 different random-looking website names within 10 minutes, which is how malware keeps making up new names to find its controller. |
| 9 | dns_tunnel | 1 | 699 (576) | 9.754 | 3.109 | 21.978 | yes | A device on your Wi-Fi made 25 long, never-repeating DNS lookups under one website, which could be used to smuggle data out or control malware, without being noticed. |
| 10 | device_anomaly | 1 | 700 (576) | 9.638 | 3.073 | 23.959 | yes | A device on your Wi-Fi is behaving strangely, sending a large amount of data in a short time, and it's also contacting new servers it never used before, which could be a sign of an attack or malware. |
| 11 | network_scan | 1 | 693 (576) | 9.192 | 3.083 | 28.004 | yes | A device on your Wi-Fi scanned many other machines in a row, trying to find weak passwords or known flaws, which is how malware spreads and takes over more devices. Normal devices connect to a few servers, and those answer, so this is a warning sign to check, not proof. |

# Flood of traffic (denial of service)
severity: high
summary: A device is sending a flood of connections to one target, to overload it so that it stops working.
pretends: a device on your Wi-Fi
wants: to knock a server or device offline
fact: Ordinary apps open a handful of connections at a time; hundreds per second to one target is an attack or a badly broken device.

## Steps
1. Find the device in the alert and disconnect it from the Wi-Fi.
2. If it is an IoT device, reset it to factory settings and update it before reconnecting.
3. If your own device or service is the target, restart it and keep an eye on the alerts.

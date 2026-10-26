# Device behaving unlike its normal self
severity: medium
summary: A device suddenly sent much more traffic than usual and talked to many servers it never used before. That can be an update, or a sign that it was taken over.
pretends: a program on one of your devices
wants: to use the device for its own purposes, or send out data
fact: Sensors and cameras talk to the same few servers every day, so a sudden jump to many new servers is worth checking.

## Steps
1. Think whether something changed (a new app, an update, a new use). If not, disconnect the device until it is checked.
2. Update the device; reset IoT devices to factory settings if the alert repeats.
3. Watch for more alerts about the same device.

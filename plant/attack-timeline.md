Example Attack Timeline

Your IDS might observe traffic like:

write coil 0 ON
write coil 0 OFF
write coil 0 ON
write coil 0 OFF

Then sensor spoofing:

tank_level = 10
tank_level = 90
tank_level = 5

These patterns simulate process manipulation attacks.

What Your IDS Can Detect
Protocol anomalies

excessive Modbus reads

unusual write commands

Process anomalies

Example rule:

pump OFF but tank level rising
Timing anomalies
control commands faster than physical system
Recommended Monitoring Tools

Use your IDS together with:

Wireshark

Zeek

Suricata

Experiments You Can Run

You can evaluate:

Experiment	Goal
oscillation attack	detect process instability
replay attack	detect duplicate commands
sensor spoofing	detect impossible physics
flood attack	detect protocol abuse

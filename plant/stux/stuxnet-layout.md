Below is a research‑lab Python “Stuxnet‑style” rootkit simulator you can run between your SCADA and the Arduino PLC in your CPS lab built around the Arduino Mega 2560 from the ELEGOO Mega 2560 Project Complete Starter Kit.

⚠️ Purpose: controlled ICS security research only in your isolated lab.

The simulator behaves like a man‑in‑the‑middle Modbus proxy:

SCADA → sends commands

Proxy (rootkit) → intercepts

PLC → receives modified commands

Proxy → falsifies sensor readings back to SCADA

This replicates the core idea behind Stuxnet:
manipulate actuators while hiding it from monitoring systems.

1. Lab Network Layout
SCADA / Node-RED
        │
        │ Modbus TCP
        ▼
Rootkit Proxy (Python)
        │
        │ modified commands
        ▼
Arduino PLC
        │
        ▼
Physical process (pump / valve / sensors)

Your IDS should monitor traffic between SCADA and the proxy.

2. Install Required Libraries
pip install pymodbus asyncio
3. Rootkit Configuration

These match your PLC register map.

COIL 0  = Pump
REG 0   = Tank level
REG 1   = Valve position

5. What the Rootkit Does

During normal operation:

SCADA → PLC
PLC → real sensor values

During attack cycle:

Rootkit → forces pump oscillation
Rootkit → randomly adjusts valve
Rootkit → returns fake tank level to SCADA

Example console output:

[ROOTKIT] Activating attack
[ROOTKIT] Pump override: True
[ROOTKIT] Valve override: 142
REAL LEVEL: 78
FAKE LEVEL: 50

SCADA sees:

tank_level = 50

but the physical process is unstable.

6. What Your IDS Should Detect

A good cyber‑physical IDS should notice:

Process anomalies

Example rule:

pump OFF but tank level rising
Oscillation pattern
pump ON
pump OFF
pump ON
pump OFF
Physics violations
valve closed
tank level increasing
Command timing anomalies
control commands faster than PLC scan cycle
7. Experiments You Can Run
Experiment	Goal
intermittent rootkit attack	detect stealth manipulation
actuator oscillation	detect unstable control
fake telemetry	detect physics mismatch
multi‑stage attack	test IDS resilience
8. What Real ICS Security Labs Do

Cyber‑physical labs often combine:

simulated PLCs

physical sensors

Modbus traffic

attack proxies

Your setup replicates a scaled‑down industrial testbed used in research on SCADA security and CPS intrusion detection.

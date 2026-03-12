Below is the complete architecture for your CPS / ICS cybersecurity testbed built around:

- ELEGOO Mega 2560 Project Complete Starter Kit
- Arduino Uno Rev3
- W5500 Ethernet Module
- MAX485 RS-485 TTL Converter Module
- TP-Link LS1005G 5-Port Gigabit Desktop Switch

This design mimics a small industrial control system while staying cheap and simple. The setup replicates many real ICS characteristics and is surprisingly close to university CPS labs.

1. Full Architecture of Your CPS / IDS Testbed

                         ┌──────────────────────┐
                         │      PC / Laptop      │
                         │                       │
                         │  SCADA Dashboard      │
                         │  IDS / IPS Engine     │
                         │  Attack Framework     │
                         │  Wireshark Monitor    │
                         └──────────┬────────────┘
                                    │
                                    │ Ethernet
                                    │
                        ┌───────────▼───────────┐
                        │   Network Switch       │
                        │   (LS1005G)            │
                        └───────────┬────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     │                             │
             ┌───────▼────────┐            ┌───────▼────────┐
             │  PLC 1         │            │  PLC 2         │
             │ Arduino Mega   │ RS-485 Bus │ Arduino Uno    │
             │ + W5500        │────────────│ + MAX485       │
             └───────┬────────┘            └───────┬────────┘
                     │                             │
                     │                             │
           ┌─────────▼──────────┐       ┌──────────▼─────────┐
           │ Actuators          │       │ Sensors             │
           │                    │       │                     │
           │ Relay (pump)       │       │ Ultrasonic (level)  │
           │ Servo (valve)      │       │ Temp/Humidity       │
           │ DC motor (fan)     │       │ Motion sensor       │
           │ Buzzer (alarm)     │       │ Sound sensor        │
           │ LED indicators     │       │ Water level sensor  │
           └────────────────────┘       └─────────────────────┘

This architecture resembles a small industrial plant network organized into Purdue model levels.

2. Level 0 — Physical Process

These simulate the real-world plant.

Component              Industrial Equivalent
Ultrasonic sensor      tank level sensor
Servo motor            valve actuator
Relay + motor          pump
Temperature sensor     coolant sensor
Water level module     safety float switch
Buzzer                 alarm system

3. Level 1 — PLC Controllers

Two microcontrollers act as PLCs in a distributed control system.

PLC 1 – Process Controller

Device:
Arduino Mega 2560

Responsibilities:
pump control
valve position
safety logic
alarm triggers
Modbus TCP server (SCADA interface)
Modbus RTU master (polls PLC 2)

PLC 2 – Sensor Node

Device:
Arduino Uno Rev3

Responsibilities:
collect sensor readings (ultrasonic, temperature, sound, motion, water level)
serve data via Modbus RTU slave (ID 1)

4. Level 2 — Industrial Network

Communication happens in two ways.

Fieldbus
RS-485 (Modbus RTU)

Between PLCs using:
MAX485 RS-485 TTL Converter Module
Twisted pair cable with 120Ω termination
9600 baud, Mega=master, Uno=slave ID 1

Plant Network
Ethernet (Modbus TCP)

Using:
W5500 Ethernet Module on PLC 1
TP-Link LS1005G 5-Port Gigabit Desktop Switch

5. Level 3 — Control / Monitoring

Your computer acts as:

SCADA interface
IDS/IPS monitoring node
attacker workstation

Tools you might run:

Wireshark
Python attack scripts
Modbus scanners
IDS detection engine

6. Network Addressing

Device               IP Address
SCADA PC             192.168.1.10
PLC 1 (Mega)         192.168.1.20
PLC 2 (Uno)          RS-485 slave ID 1 (no IP, accessed through PLC 1)

7. Turning the Arduinos into a Distributed PLC

PLC 1 (Mega) runs a scan cycle every 200ms:

1 Poll sensor node (Modbus RTU read from Uno)
2 Execute control logic
3 Security checks
4 Update actuator outputs
5 Sync Modbus TCP registers
6 Update HMI
7 Send telemetry

PLC 2 (Uno) runs continuously:

1 Read all sensor inputs
2 Update Modbus holding registers
3 Respond to RTU master polls

This replicates real distributed PLC architectures where sensor I/O modules are separate from the main controller.

8. Example Process You Will Simulate

A water treatment / pumping system.

          Tank
       ┌──────────┐
Valve →│          │→ Pump → Outflow
       │          │
       └──────────┘
         Level Sensor

Control rules:

IF tank < 30%
    start pump

IF tank > 85%
    stop pump

IF pump ON and valve closed
    alarm

This creates realistic physical constraints for IDS detection.

9. Communication for IDS Testing

Modbus TCP register table (exposed by PLC 1 on port 502):

Register    Value
Coil 0      pump state
Reg 0       tank level
Reg 1       valve position
Reg 2       temperature
Reg 3       sound level
Reg 4       ultrasonic distance
Reg 5       alarm state

SCADA polls these registers. Your IDS watches traffic between SCADA and PLC 1.

Modbus RTU register table (on PLC 2, polled by PLC 1):

Register    Value
Reg 0       ultrasonic distance
Reg 1       temperature
Reg 2       sound level
Reg 3       motion detected
Reg 4       water level

IDS can also monitor RS-485 bus traffic for fieldbus anomalies.

10. Data Flow in Your Testbed

Sensor → Uno (PLC 2) → RS-485 Modbus RTU → Mega (PLC 1) → Ethernet Modbus TCP → Switch → SCADA
                                                   │
                                                   │
                                                  IDS
                                                   │
                                                Attacker

Your IDS watches traffic at the Ethernet level between SCADA and PLC 1.

11. Attack Simulation Paths

Your lab allows multiple cyber-physical attacks.

Command Injection
Attacker → Modbus TCP → PLC 1

Example:
Write coil: Pump = OFF

Sensor Spoofing
PLC 2 → fake sensor value → PLC 1

Example:
Level = 10%
Pump runs continuously.

Stuxnet-Style Manipulation
MitM proxy between SCADA and PLC

Behavior:
Pump oscillates
but reports normal values

Network Reconnaissance
Tools scan for:
Modbus port 502 on 192.168.1.20

12. IDS Detection Points

Your IDS can monitor:

Network anomalies
unexpected Modbus commands
abnormal polling frequency
unauthorized IP addresses

Process anomalies

Example:
pump OFF but tank level rising

This indicates sensor spoofing.

Physics-based detection rules:

IF pump_state == OFF
AND tank_level increasing
THEN alert

IF command frequency > threshold
THEN possible control attack

13. Observable Attack Indicators

Protocol anomaly
sudden repeated Modbus writes

Process anomaly
pump ON
tank level increasing too fast

Physics violation
pump OFF
but tank level still rising

These are cyber-physical detection rules.

14. Realism Compared to Industrial Systems

Feature          Lab                   Real ICS
PLC controllers  Arduino Mega + Uno    Siemens / Rockwell
Fieldbus         RS-485 Modbus RTU     Modbus RTU / Profibus
Control network  Ethernet Modbus TCP   Industrial Ethernet
SCADA            PC                    SCADA server
Process          simulated             physical plant

15. Final Lab Capability

Your system can simulate:

distributed PLC control
Modbus RTU fieldbus
Modbus TCP network traffic
cyber-physical attacks
anomaly-based IDS detection

Essentially a mini industrial cyber-range.

16. Experiments You Can Run

Your testbed can support research experiments like:

Attack types

command injection
replay attacks
sensor spoofing
timing attacks
process manipulation
Stuxnet-style MitM

IDS approaches

signature IDS
anomaly detection
ML-based IDS
physics-based IDS

17. What Universities Use Similar Labs For

Small ICS labs like this are used for research on:

SCADA security
industrial malware
process-aware intrusion detection
cyber-physical resilience

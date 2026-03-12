Below is a complete wiring plan for your CPS / ICS mini-lab using:

- Arduino Mega 2560 (ELEGOO kit) — PLC 1 Process Controller
- Arduino Uno Rev3 — PLC 2 Sensor Node
- W5500 Ethernet Module — Modbus TCP
- MAX485 RS-485 TTL Converter Module — Modbus RTU fieldbus
- TP-Link LS1005G 5-Port Gigabit Desktop Switch — plant network

The wiring is organized by industrial subsystem so it's easier to build and debug.

1. Overall CPS Wiring Architecture

Two PLCs form a distributed control system connected via RS-485 fieldbus and Ethernet plant network.

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

2. Power Distribution

Create stable power rails on each breadboard.

PLC 1 (Mega):
Mega 5V  → Breadboard +
Mega GND → Breadboard –

PLC 2 (Uno):
Uno 5V   → Breadboard +
Uno GND  → Breadboard –

Modules powered from the rails:
W5500, RFID, LCD, relay module, servo, MAX485 modules

⚠️ Motors should not draw directly from Arduino pins.

Use:
L293D motor driver
relay module

3. PLC 1 — Arduino Mega 2560 (Process Controller)

3a. W5500 Ethernet Module

Provides Modbus TCP on the plant network.

W5500    Mega
─────    ────
MOSI  →  D51 (SPI)
MISO  →  D50 (SPI)
SCK   →  D52 (SPI)
CS    →  D10
GND   →  GND
5V    →  5V

RJ45 port → TP-Link LS1005G switch

Shares SPI bus with RFID (different CS pins: W5500=D10, RFID=D53).

IP address: 192.168.1.20

3b. MAX485 RS-485 Module (RTU Master Side)

Connects to Uno sensor node via RS-485 bus.

MAX485   Mega
──────   ────
DI    →  TX1 (D18)
RO    →  RX1 (D19)
DE    →  D2
RE    →  D2
VCC   →  5V
GND   →  GND

A/B terminals → twisted pair → Uno MAX485 A/B

3c. Pump System

Pump simulated with 3–6V DC motor + relay.

Relay Module
VCC → 5V
GND → GND
IN  → D8

Relay contacts:
COM → power source +
NO  → motor +
motor – → GND

Logic:
Arduino HIGH → pump ON
Arduino LOW  → pump OFF

3d. Valve Control (Servo)

Servo represents industrial valve actuator.

Red    → 5V
Brown  → GND
Orange → D9

Valve positions:
0°   closed
90°  half open
180° full open

3e. Flow Visualization Motor

Use fan blade motor with L293D driver.

L293D Wiring
Pin 1  → 5V
Pin 2  → D10
Pin 7  → D11
Pin 3  → Motor +
Pin 6  → Motor –
Pin 4  → GND
Pin 5  → GND
Pin 8  → External motor supply

This simulates pipeline flow movement.

3f. Operator HMI Panel (LCD 16x2)

VSS → GND
VDD → 5V
VO  → potentiometer
RS  → D22
RW  → GND
E   → D23

D4  → D24
D5  → D25
D6  → D26
D7  → D27

Used for:
Tank level
Pump state
Valve position
Temperature

3g. Rotary Encoder (Manual Control)

CLK → D30
DT  → D31
SW  → D32
VCC → 5V
GND → GND

Use to adjust valve opening manually.

3h. Alarm System

Active Buzzer
+ → D12
- → GND

Alarm LEDs
Red LED    → D33
Yellow LED → D34
Green LED  → D35

With 220Ω resistors.

Meaning:
green  = normal
yellow = warning
red    = critical

3i. RFID Operator Authentication

SDA  → D53
SCK  → D52 (SPI)
MOSI → D51 (SPI)
MISO → D50 (SPI)
RST  → D5
GND  → GND
3.3V → 3.3V

Functions:
scan card
enable manual override
log operator activity

3j. Real Time Clock

VCC → 5V
GND → GND
SDA → D20
SCL → D21

Used for:
attack logging
process data timestamps
alarm history

3k. LED Matrix (Process Visualization)

VCC → 5V
GND → GND
DIN → D40
CS  → D41
CLK → D42

Example display:
tank level graph
pump speed indicator

4. PLC 2 — Arduino Uno Rev3 (Sensor Node)

4a. MAX485 RS-485 Module (RTU Slave Side)

Connects to Mega process controller via RS-485 bus.

MAX485   Uno
──────   ───
DI    →  TX (D1)
RO    →  RX (D0)
DE    →  D2
RE    →  D2
VCC   →  5V
GND   →  GND

A/B terminals → twisted pair → Mega MAX485 A/B

Note: Serial (D0/D1) is used for Modbus RTU. USB debug unavailable during operation.

4b. Ultrasonic Sensor (Tank Height)

VCC  → 5V
GND  → GND
TRIG → D7
ECHO → D6

Used to measure water level distance.

4c. Water Level Sensor

S  → A0
+  → 5V
-  → GND

Simulates industrial level transmitter.

4d. Temperature Sensor

VCC → 5V
GND → GND
OUT → A1

Simulates plant coolant sensor.

4e. Sound Sensor (Machine Vibration)

VCC → 5V
GND → GND
OUT → A2

4f. Motion Sensor (Facility Intrusion)

VCC → 5V
GND → GND
OUT → D3

5. RS-485 Fieldbus Wiring

Connect the two MAX485 modules with a twisted pair cable.

Mega MAX485 A  ──── twisted pair ────  Uno MAX485 A
Mega MAX485 B  ──── twisted pair ────  Uno MAX485 B

Add 120Ω termination resistors at each end of the bus (across A and B) if using long cable runs.

Communication: Modbus RTU at 9600 baud. Mega is master, Uno is slave ID 1.

6. Plant Network (Ethernet)

TP-Link LS1005G switch ports:

Port 1 → PC / Laptop (SCADA + IDS + Attacker)
Port 2 → PLC 1 (Mega W5500 RJ45)
Port 3-5 → available for expansion

IP addressing:
SCADA PC     192.168.1.10
PLC 1 (Mega) 192.168.1.20

Protocol: Modbus TCP on port 502.

7. Final System Map

RFID ───┐         ┌─── LCD HMI
        │         │
        ▼         ▼
   ┌───────────────────────────────┐
   │     PLC 1: Arduino Mega      │
   │     (Process Controller)     │
   │                               │
   │ Actuators       Network       │
   │  pump relay      W5500 ETH   │
   │  servo valve     RS-485 bus  │
   │  flow motor                   │
   │  buzzer/LEDs                  │
   │                               │
   │ Security                      │
   │  RFID auth                    │
   │  RTC logging                  │
   └───────────┬──────────┬────────┘
               │          │
           RS-485     Ethernet
               │          │
   ┌───────────▼──────┐   │
   │  PLC 2: Uno      │   │
   │  (Sensor Node)   │   │
   │                   │   │
   │  ultrasonic       │   │
   │  water level      │   │
   │  temperature      │   ├─── LS1005G Switch
   │  sound            │   │         │
   │  motion           │   │         │
   └───────────────────┘   │    SCADA + IDS
                           │
                           └─── PC / Laptop

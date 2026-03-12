Below is a research-oriented Python attack simulation framework you can use against your Arduino CPS testbed. It generates realistic industrial control system (ICS) attack traffic so you can evaluate your IDS/IPS.

The framework targets a PLC-style device like your Arduino Mega 2560 and can simulate attacks conceptually similar to the behaviour of Stuxnet, but safely in a lab.

The framework supports attacks such as:

command injection

replay attacks

sensor spoofing

control oscillation

protocol flooding

Architecture of the Attack Framework
Attacker Machine
│
├── Attack Controller
│
├── Modbus Attack Engine
│
├── Process Manipulation Attacks
│
└── Traffic Generation
        │
        ▼
    PLC (Arduino Mega)

Your IDS observes the communication between the attacker and the PLC.

Python Attack Framework

Install dependencies first:

pip install pymodbus

can a modbus plc be made out of ELEGOO UNO Project Super Starter Kit Tutorial?

Yes — you can build a simple Modbus-compatible device using the Arduino Uno from the ELEGOO UNO Project Super Starter Kit, but there are some important limitations. It won’t be a full industrial PLC, yet it can act like a small Modbus slave device for learning, testing, or simple automation.

What the kit already gives you
4

The kit typically includes:

Arduino Uno compatible board

Breadboard

LEDs, buttons

Sensors (temperature, light, etc.)

Relay module

LCD

Jump wires

With these parts you can already simulate PLC-style I/O:

Digital inputs → buttons, switches

Digital outputs → LEDs, relay

Analog inputs → sensors

What you need to add for Modbus

The kit does NOT include the communication hardware needed for Modbus RTU.

You will usually need:

For Modbus RTU (most common in PLCs):

RS-485 module (MAX485 or similar)

120Ω termination resistor (often already on module)

Example module:

MAX485 TTL-to-RS485 converter

This lets the Arduino communicate on an industrial RS-485 bus.

Software libraries

On the Arduino you can run Modbus libraries such as:

ModbusRTU

SimpleModbus

ArduinoModbus (by Arduino)

These allow the Arduino to act as:

Modbus slave/server (typical PLC device)

Modbus master/client

Example architecture
Modbus Master (SCADA / PLC / PC)
          │
       RS-485 bus
          │
     MAX485 module
          │
       Arduino Uno
          │
   Sensors / Relays / LEDs

Example mapping:

Modbus Address	Function
Coil 0	LED output
Coil 1	Relay output
Input 0	Button
Holding Reg 0	Temperature sensor
Example simple Arduino Modbus slave code concept
#include <ModbusRTU.h>

ModbusRTU mb;

bool led;

void setup() {
  pinMode(13, OUTPUT);
  Serial.begin(9600);

  mb.begin(&Serial);
  mb.slave(1);

  mb.addCoil(0);
}

void loop() {
  mb.task();
  digitalWrite(13, mb.Coil(0));
}

This would allow a Modbus master to turn the Arduino LED on/off.

Limitations vs real PLC
Arduino PLC	Industrial PLC
No electrical isolation	Industrial isolation
Not industrial-rated	Industrial reliability
Limited I/O	Expandable I/O
No ladder logic	Ladder / FBD programming
No watchdog safety	Built-in safety

But for:

learning Modbus

SCADA experiments

home automation

protocol testing

…it works very well.

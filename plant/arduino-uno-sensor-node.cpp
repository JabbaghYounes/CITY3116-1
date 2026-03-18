#include <ModbusRTUSlave.h>
#include <DHT.h>

/* ===============================
   PLC 2 — Sensor Node
   Arduino Uno Rev3 + MAX485 RS-485
   Modbus RTU slave (ID 1)
   Polled by PLC 1 (Mega) over RS-485
================================ */

/* ===============================
   PIN DEFINITIONS
================================ */

#define TRIG_PIN 7
#define ECHO_PIN 6
#define WATER_SENSOR A0
#define DHT_PIN 4
#define SOUND_SENSOR A2
#define MOTION_PIN 3
#define MAX485_DE 2

/* DHT11 temperature + humidity sensor */
DHT dht(DHT_PIN, DHT11);

/* ===============================
   MODBUS RTU SLAVE
================================ */

/* MAX485: DI→TX(1), RO→RX(0), DE+RE→D2 */
ModbusRTUSlave modbus(Serial, MAX485_DE);

/* Holding register map (read by PLC 1):
   Reg 0: ultrasonic distance (cm)
   Reg 1: temperature (Celsius, integer, from DHT11)
   Reg 2: sound level (raw ADC 0-1023)
   Reg 3: motion detected (0/1)
   Reg 4: water level (raw ADC 0-1023)
*/

uint16_t holdingRegisters[5];

/* ===============================
   SETUP
================================ */

void setup() {

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  pinMode(MOTION_PIN, INPUT);

  dht.begin();

  modbus.configureHoldingRegisters(holdingRegisters, 5);
  modbus.begin(1, 9600); /* slave ID 1, 9600 baud */

}

/* ===============================
   MAIN LOOP
================================ */

void loop() {

  /* update sensor readings */

  holdingRegisters[0] = measureDistance();

  /* DHT11 returns float; cast to integer Celsius for Modbus register */
  float t = dht.readTemperature();
  holdingRegisters[1] = isnan(t) ? 0 : (uint16_t)t;

  holdingRegisters[2] = analogRead(SOUND_SENSOR);
  holdingRegisters[3] = digitalRead(MOTION_PIN);
  holdingRegisters[4] = analogRead(WATER_SENSOR);

  /* respond to RTU master requests */

  modbus.poll();

}

/* ===============================
   ULTRASONIC MEASUREMENT
================================ */

long measureDistance() {

  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);

  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);

  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH);
  long distance = duration * 0.034 / 2;

  return distance;

}

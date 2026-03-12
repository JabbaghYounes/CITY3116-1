#include <SPI.h>
#include <Ethernet.h>
#include <ArduinoModbus.h>
#include <ModbusMaster.h>
#include <Servo.h>
#include <Wire.h>
#include <LiquidCrystal.h>
#include <MFRC522.h>

/* ===============================
   PLC 1 — Process Controller
   Arduino Mega 2560 + W5500 Ethernet
   Modbus TCP server (SCADA facing)
   Modbus RTU master (polls Uno sensor node)
================================ */

/* ===============================
   PIN DEFINITIONS
================================ */

/* Actuators */
#define PUMP_RELAY 8
#define SERVO_PIN 9
#define BUZZER 12

/* MAX485 RS-485 direction (Serial1: TX1=18, RX1=19) */
#define MAX485_DE 2

/* W5500 Ethernet CS (shares SPI bus with RFID) */
#define ETH_CS 10

/* RFID */
#define RFID_SS 53
#define RFID_RST 5

/* LCD */
LiquidCrystal lcd(22,23,24,25,26,27);

/* RFID */
MFRC522 rfid(RFID_SS, RFID_RST);

/* Servo */
Servo valveServo;

/* ===============================
   NETWORK CONFIGURATION
================================ */

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x01 };
IPAddress ip(192, 168, 1, 20);

EthernetServer ethServer(502);
ModbusTCPServer modbusTCPServer;
EthernetClient currentClient;

/* ===============================
   MODBUS RTU MASTER (polling Uno)
================================ */

ModbusMaster rtuNode;

void preTransmission() {
  digitalWrite(MAX485_DE, HIGH);
}

void postTransmission() {
  digitalWrite(MAX485_DE, LOW);
}

/* ===============================
   MODBUS TCP REGISTER MAP
================================ */

/* Coil 0:        pump state (R/W)
   Holding Reg 0: tank level (raw ADC)
   Holding Reg 1: valve position (degrees)
   Holding Reg 2: temperature (raw ADC)
   Holding Reg 3: sound level (raw ADC)
   Holding Reg 4: ultrasonic distance (cm)
   Holding Reg 5: alarm state (0/1)
*/

#define NUM_COILS 1
#define NUM_HOLDING_REGS 6

/* ===============================
   PROCESS VARIABLES
================================ */

int tankLevel = 0;
int temperature = 0;
int soundLevel = 0;
int ultrasonicDist = 0;

bool pumpState = false;
int valvePosition = 90;

bool alarmState = false;
bool intrusionState = false;

unsigned long lastScan = 0;
unsigned long scanInterval = 200;

/* security */
bool operatorAuthorized = false;
unsigned long authTimeout = 0;

/* anomaly detection */
int lastTankLevel = 0;

/* ===============================
   SETUP
================================ */

void setup() {

  Serial.begin(9600);

  /* actuator pins */
  pinMode(PUMP_RELAY, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  valveServo.attach(SERVO_PIN);

  /* MAX485 direction control */
  pinMode(MAX485_DE, OUTPUT);
  digitalWrite(MAX485_DE, LOW);

  /* LCD */
  lcd.begin(16,2);
  lcd.print("CPS PLC BOOT");

  /* SPI bus (shared: W5500 CS=10, RFID CS=53) */
  SPI.begin();

  /* RFID */
  rfid.PCD_Init();

  /* W5500 Ethernet */
  Ethernet.begin(mac, ip);
  ethServer.begin();

  /* Modbus TCP server */
  modbusTCPServer.begin();
  modbusTCPServer.configureCoils(0, NUM_COILS);
  modbusTCPServer.configureHoldingRegisters(0, NUM_HOLDING_REGS);

  /* Modbus RTU master on Serial1 via MAX485 to Uno */
  Serial1.begin(9600);
  rtuNode.begin(1, Serial1);
  rtuNode.preTransmission(preTransmission);
  rtuNode.postTransmission(postTransmission);

  delay(2000);
  lcd.clear();

  Serial.print("PLC 1 online at ");
  Serial.println(Ethernet.localIP());
}

/* ===============================
   PLC SCAN LOOP
================================ */

void loop() {

  handleModbusTCP();

  if(millis() - lastScan >= scanInterval){

    pollSensorNode();
    processLogic();
    securityChecks();
    updateOutputs();
    updateModbusRegisters();
    updateHMI();
    telemetry();

    lastScan = millis();
  }

}

/* ===============================
   MODBUS TCP HANDLER
================================ */

void handleModbusTCP() {

  EthernetClient client = ethServer.available();

  if(client){
    currentClient = client;
    modbusTCPServer.accept(currentClient);
  }

  if(currentClient && currentClient.connected()){
    modbusTCPServer.poll();

    /* apply SCADA writes to process */
    pumpState = modbusTCPServer.coilRead(0);
    int reqValve = modbusTCPServer.holdingRegisterRead(1);
    if(reqValve >= 0 && reqValve <= 180){
      valvePosition = reqValve;
    }
  }
}

/* ===============================
   POLL SENSOR NODE (Uno via RTU)
================================ */

void pollSensorNode() {

  uint8_t result = rtuNode.readHoldingRegisters(0, 5);

  if(result == rtuNode.ku8MBSuccess){
    ultrasonicDist  = rtuNode.getResponseBuffer(0);
    temperature     = rtuNode.getResponseBuffer(1);
    soundLevel      = rtuNode.getResponseBuffer(2);
    intrusionState  = rtuNode.getResponseBuffer(3);
    tankLevel       = rtuNode.getResponseBuffer(4);
  }
}

/* ===============================
   PROCESS CONTROL LOGIC
================================ */

void processLogic(){

  int tankPercent = map(tankLevel,0,1023,0,100);

  /* pump control */

  if(tankPercent < 30){
    pumpState = true;
  }

  if(tankPercent > 85){
    pumpState = false;
  }

  /* valve regulation */

  if(pumpState){
    valvePosition = 120;
  }else{
    valvePosition = 40;
  }

  /* temperature alarm */

  if(temperature > 700){
    alarmState = true;
  }

}

/* ===============================
   SECURITY SYSTEM
================================ */

void securityChecks(){

  /* RFID AUTHENTICATION */

  if(rfid.PICC_IsNewCardPresent()){
    if(rfid.PICC_ReadCardSerial()){

      operatorAuthorized = true;
      authTimeout = millis();

      lcd.clear();
      lcd.print("Operator Auth");
      delay(1000);
    }
  }

  if(operatorAuthorized){
    if(millis() - authTimeout > 30000){
      operatorAuthorized = false;
    }
  }

  /* intrusion detection */

  if(intrusionState){
    alarmState = true;
  }

  /* physics anomaly detection */

  if(!pumpState && tankLevel > lastTankLevel + 10){
    Serial.println("ANOMALY: Tank rising while pump OFF");
    alarmState = true;
  }

  lastTankLevel = tankLevel;

}

/* ===============================
   OUTPUT CONTROL
================================ */

void updateOutputs(){

  /* pump */

  if(pumpState){
    digitalWrite(PUMP_RELAY,HIGH);
  }else{
    digitalWrite(PUMP_RELAY,LOW);
  }

  /* valve */

  valveServo.write(valvePosition);

  /* alarm */

  if(alarmState){
    digitalWrite(BUZZER,HIGH);
  }else{
    digitalWrite(BUZZER,LOW);
  }

}

/* ===============================
   SYNC STATE TO MODBUS TCP
================================ */

void updateModbusRegisters(){

  modbusTCPServer.coilWrite(0, pumpState);
  modbusTCPServer.holdingRegisterWrite(0, tankLevel);
  modbusTCPServer.holdingRegisterWrite(1, valvePosition);
  modbusTCPServer.holdingRegisterWrite(2, temperature);
  modbusTCPServer.holdingRegisterWrite(3, soundLevel);
  modbusTCPServer.holdingRegisterWrite(4, ultrasonicDist);
  modbusTCPServer.holdingRegisterWrite(5, alarmState);

}

/* ===============================
   HUMAN MACHINE INTERFACE
================================ */

void updateHMI(){

  lcd.setCursor(0,0);

  lcd.print("L:");
  lcd.print(map(tankLevel,0,1023,0,100));
  lcd.print("% ");

  lcd.print("P:");
  if(pumpState){
    lcd.print("ON ");
  }else{
    lcd.print("OFF");
  }

  lcd.setCursor(0,1);

  lcd.print("V:");
  lcd.print(valvePosition);

  lcd.print(" T:");
  lcd.print(map(temperature,0,1023,0,50));

}

/* ===============================
   TELEMETRY OUTPUT
================================ */

void telemetry(){

  Serial.print("LEVEL:");
  Serial.print(tankLevel);

  Serial.print(",TEMP:");
  Serial.print(temperature);

  Serial.print(",PUMP:");
  Serial.print(pumpState);

  Serial.print(",VALVE:");
  Serial.print(valvePosition);

  Serial.print(",ALARM:");
  Serial.print(alarmState);

  Serial.println();

}

/* ===============================
   MANUAL CONTROL FUNCTIONS
================================ */

void manualPumpToggle(){

  if(operatorAuthorized){
    pumpState = !pumpState;
  }

}

void resetAlarm(){

  if(operatorAuthorized){
    alarmState = false;
  }

}

/* ===============================
   ATTACK SIMULATION HOOK
================================ */

void simulatedAttack(){

  /* emulate malicious pump oscillation */

  pumpState = true;
  delay(500);

  pumpState = false;
  delay(500);

}

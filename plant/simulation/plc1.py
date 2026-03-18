"""
PLC 1 — Process Controller (Arduino Mega equivalent)

Polls PLC2 for sensor data via Modbus TCP (simulates RS-485 RTU fieldbus).
Runs control logic (pump, valve, alarm).
Serves Modbus TCP registers to SCADA and attack tools on port 502.

Modbus TCP Register Map (SCADA-facing):
  Coil 0:  pump state (R/W)
  Reg 0:   tank level (raw ADC)
  Reg 1:   valve position (degrees)
  Reg 2:   temperature (raw ADC)
  Reg 3:   sound level (raw ADC)
  Reg 4:   ultrasonic distance (cm)
  Reg 5:   alarm state (0/1)
"""

import threading
import time
import sys

from pymodbus.server import StartTcpServer
from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext
)

from utils import (
    PLC, STATE, PLC2_ADDR, PLC2_PORT, MODBUS_PORT, PLC_PERIOD,
    PUMP_STATE, VALVE_POS, ALARM_STATE,
    TANK_LEVEL, TEMPERATURE, SOUND_LEVEL, ULTRASONIC, MOTION
)


class WaterTreatmentPLC1(PLC):

    def pre_loop(self, sleep=0.1):

        # ---- Modbus TCP server (SCADA / attack surface) ----

        self.mb_store = ModbusDeviceContext(
            di=ModbusSequentialDataBlock(0, [0] * 10),
            co=ModbusSequentialDataBlock(0, [0] * 10),
            hr=ModbusSequentialDataBlock(0, [0] * 10),
            ir=ModbusSequentialDataBlock(0, [0] * 10),
        )
        self.mb_context = ModbusServerContext(
            devices=self.mb_store, single=True
        )

        def run_server():
            StartTcpServer(
                context=self.mb_context,
                address=("0.0.0.0", MODBUS_PORT)
            )

        self.mb_thread = threading.Thread(target=run_server)
        self.mb_thread.daemon = True
        self.mb_thread.start()

        print("[PLC1] Modbus TCP server on port", MODBUS_PORT)

        # ---- Modbus TCP client (polls PLC2 sensor node) ----

        self.plc2_client = ModbusTcpClient(PLC2_ADDR, port=PLC2_PORT)
        connected = False
        for attempt in range(10):
            if self.plc2_client.connect():
                connected = True
                break
            print("[PLC1] Waiting for PLC2...")
            time.sleep(1)

        if not connected:
            print("[PLC1] WARNING: Could not connect to PLC2")

        # ---- Internal state ----

        self.pump_state = 0
        self.valve_position = 90
        self.alarm_state = 0
        self.last_tank_level = 500

        time.sleep(sleep)

    def main_loop(self):

        print("[PLC1] Process controller running")

        while True:

            # ================================================
            #  1. Poll sensor node (PLC2) via Modbus TCP
            # ================================================

            tank_level = 500
            temperature = 300
            sound_level = 100
            ultrasonic = 50
            motion = 0

            rr = self.plc2_client.read_holding_registers(0, count=5)
            if rr and not rr.isError():
                ultrasonic  = rr.registers[0]
                temperature = rr.registers[1]
                sound_level = rr.registers[2]
                motion      = rr.registers[3]
                tank_level  = rr.registers[4]

            # ================================================
            #  2. Check for SCADA writes (via Modbus TCP)
            # ================================================

            scada_pump = self.mb_store.getValues(1, 0, count=1)[0]
            scada_valve = self.mb_store.getValues(3, 1, count=1)[0]

            # Apply SCADA overrides if non-zero
            if scada_pump:
                self.pump_state = int(scada_pump)
            if 0 < scada_valve <= 180:
                self.valve_position = int(scada_valve)

            # ================================================
            #  3. Process control logic
            #     (mirrors arduino-plc-firmware.cpp)
            # ================================================

            tank_percent = int(tank_level * 100 / 1023) if tank_level > 0 else 0

            if tank_percent < 30:
                self.pump_state = 1

            if tank_percent > 85:
                self.pump_state = 0

            # Valve tracks pump state
            if self.pump_state:
                self.valve_position = 120
            else:
                self.valve_position = 40

            # ================================================
            #  4. Security checks
            # ================================================

            self.alarm_state = 0

            # Temperature alarm
            if temperature > 700:
                self.alarm_state = 1

            # Intrusion alarm
            if motion:
                self.alarm_state = 1

            # Physics anomaly: tank rising while pump OFF
            if not self.pump_state and tank_level > self.last_tank_level + 10:
                print("[PLC1] ANOMALY: Tank rising while pump OFF")
                self.alarm_state = 1

            self.last_tank_level = tank_level

            # ================================================
            #  5. Write actuator commands to state DB
            #     (physical_process.py reads these)
            # ================================================

            self.set(PUMP_STATE, self.pump_state)
            self.set(VALVE_POS, self.valve_position)
            self.set(ALARM_STATE, self.alarm_state)

            # ================================================
            #  6. Update Modbus TCP registers (SCADA-facing)
            # ================================================

            self.mb_store.setValues(1, 0, [self.pump_state])
            self.mb_store.setValues(3, 0, [
                tank_level,
                self.valve_position,
                temperature,
                sound_level,
                ultrasonic,
                self.alarm_state,
            ])

            # ================================================
            #  7. Telemetry (matches Arduino serial output)
            # ================================================

            print(
                "LEVEL:{},TEMP:{},PUMP:{},VALVE:{},ALARM:{}".format(
                    tank_level, temperature, self.pump_state,
                    self.valve_position, self.alarm_state
                )
            )

            time.sleep(PLC_PERIOD)


if __name__ == '__main__':
    try:
        plc1 = WaterTreatmentPLC1(
            name='plc1',
            protocol=None,
            state=STATE
        )
    except KeyboardInterrupt:
        print("\n[PLC1] Stopped")
        sys.exit(0)

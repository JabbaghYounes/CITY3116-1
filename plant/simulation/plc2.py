"""
PLC 2 — Sensor Node (Arduino Uno equivalent)

Reads sensor values from the state DB (written by physical process)
and serves them via Modbus TCP for PLC1 to poll.

In hardware, this is Modbus RTU over RS-485.
In simulation, we use Modbus TCP (Mininet provides the network).

Modbus Holding Register Map (polled by PLC1):
  Reg 0: ultrasonic distance (cm)
  Reg 1: temperature (raw ADC)
  Reg 2: sound level (raw ADC)
  Reg 3: motion detected (0/1)
  Reg 4: water level / tank level (raw ADC)
"""

import threading
import time
import sys

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext
)

from utils import (
    PLC, STATE, PLC2_ADDR, MODBUS_PORT,
    TANK_LEVEL, TEMPERATURE, SOUND_LEVEL, ULTRASONIC, MOTION
)


class SensorNodePLC2(PLC):

    def pre_loop(self, sleep=0.1):

        # Modbus TCP datastore — matches Arduino Uno register map
        self.mb_store = ModbusDeviceContext(
            di=ModbusSequentialDataBlock(0, [0] * 10),
            co=ModbusSequentialDataBlock(0, [0] * 10),
            hr=ModbusSequentialDataBlock(0, [0] * 10),
            ir=ModbusSequentialDataBlock(0, [0] * 10),
        )
        self.mb_context = ModbusServerContext(
            devices=self.mb_store, single=True
        )

        # Start Modbus TCP server in background thread
        def run_server():
            StartTcpServer(
                context=self.mb_context,
                address=("0.0.0.0", MODBUS_PORT)
            )

        self.mb_thread = threading.Thread(target=run_server)
        self.mb_thread.daemon = True
        self.mb_thread.start()

        print("[PLC2] Modbus TCP server on port", MODBUS_PORT)
        time.sleep(sleep)

    def main_loop(self):

        print("[PLC2] Sensor node running")

        while True:

            # Read sensor values from state DB
            # (physical_process.py writes these)

            ultrasonic  = int(float(self.get(ULTRASONIC)))
            temperature = int(float(self.get(TEMPERATURE)))
            sound_level = int(float(self.get(SOUND_LEVEL)))
            motion      = int(float(self.get(MOTION)))
            water_level = int(float(self.get(TANK_LEVEL)))

            # Update Modbus holding registers
            # Register map matches arduino-uno-sensor-node.cpp

            self.mb_store.setValues(3, 0, [
                ultrasonic,
                temperature,
                sound_level,
                motion,
                water_level,
            ])

            time.sleep(0.1)


if __name__ == '__main__':
    try:
        plc2 = SensorNodePLC2(
            name='plc2',
            protocol=None,
            state=STATE
        )
    except KeyboardInterrupt:
        print("\n[PLC2] Stopped")
        sys.exit(0)

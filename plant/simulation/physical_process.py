"""
Water Treatment Plant — Physical Process Simulation

Simulates tank fluid dynamics, temperature, and environmental sensors.
Reads actuator commands from the state DB (written by PLC1).
Writes sensor values to the state DB (read by PLC2).
"""

import random
import time
import sys

from utils import (
    SQLiteState, STATE,
    TANK_LEVEL, TEMPERATURE, SOUND_LEVEL, ULTRASONIC, MOTION,
    PUMP_STATE, VALVE_POS,
    FILL_RATE, DRAIN_RATE, CYCLE_TIME
)


class WaterTreatmentProcess:

    def __init__(self):
        self.state = SQLiteState(STATE)

        # Initial conditions
        self.tank = float(self.state.get(TANK_LEVEL))
        self.temp = float(self.state.get(TEMPERATURE))

    def get(self, tag):
        return self.state.get(tag)

    def set(self, tag, value):
        self.state.set(tag, value)

    def run(self):

        print("[PROCESS] Physical simulation started")

        while True:

            # ---- Read actuator states (set by PLC1) ----

            pump = int(float(self.get(PUMP_STATE)))
            valve = int(float(self.get(VALVE_POS)))

            # ---- Tank fluid dynamics ----
            # Inflow depends on pump state and valve opening
            # Outflow is constant gravity drain

            if pump:
                valve_factor = valve / 180.0
                inflow = FILL_RATE * valve_factor
            else:
                inflow = 0

            outflow = DRAIN_RATE

            self.tank += inflow - outflow
            self.tank = max(0, min(1023, self.tank))

            # ---- Temperature model ----
            # Process heat from pump operation

            if pump:
                self.temp += random.uniform(0.2, 0.8)
            else:
                self.temp -= random.uniform(0.1, 0.5)

            self.temp = max(200, min(600, self.temp))

            # ---- Sound level ----
            # Base ambient noise + pump mechanical noise

            base_noise = random.randint(50, 150)
            pump_noise = 300 if pump else 0
            sound = base_noise + pump_noise

            # ---- Ultrasonic distance ----
            # Inversely proportional to tank level
            # Full tank (1023) → 10 cm, empty (0) → 100 cm

            ultrasonic = int(100 - (self.tank / 1023.0 * 90))

            # ---- Motion sensor ----
            # Random intrusion events (2% chance per cycle)

            motion = 1 if random.random() < 0.02 else 0

            # ---- Write sensor values to state DB ----

            self.set(TANK_LEVEL, int(self.tank))
            self.set(TEMPERATURE, int(self.temp))
            self.set(SOUND_LEVEL, sound)
            self.set(ULTRASONIC, ultrasonic)
            self.set(MOTION, motion)

            time.sleep(CYCLE_TIME)


if __name__ == '__main__':
    try:
        proc = WaterTreatmentProcess()
        proc.run()
    except KeyboardInterrupt:
        print("\n[PROCESS] Stopped")
        sys.exit(0)

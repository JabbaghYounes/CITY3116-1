"""
Water Treatment Plant Simulation — Shared Configuration

Mirrors the Arduino Mega + Uno distributed PLC architecture.
Uses MiniCPS if available, otherwise provides compatible fallback classes.
"""

import os
import sqlite3
import time

# ================================================
#  File paths
# ================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'plant_db.sqlite')

# ================================================
#  MiniCPS compatibility layer
# ================================================

try:
    from minicps.devices import PLC
    from minicps.states import SQLiteState
except (ImportError, SyntaxError):

    class SQLiteState:
        """Minimal MiniCPS-compatible SQLite state backend."""

        def __init__(self, state):
            self._path = state['path']
            self._name = state['name']

        def _connect(self):
            conn = sqlite3.connect(self._path, timeout=10)
            conn.execute('PRAGMA journal_mode=WAL')
            return conn

        def get(self, what):
            conn = self._connect()
            c = conn.cursor()
            c.execute(
                "SELECT val FROM {} WHERE name=? AND pid=?".format(
                    self._name),
                (what[0], what[1])
            )
            row = c.fetchone()
            conn.close()
            return row[0] if row else '0'

        def set(self, what, value):
            conn = self._connect()
            c = conn.cursor()
            c.execute(
                "UPDATE {} SET val=? WHERE name=? AND pid=?".format(
                    self._name),
                (str(value), what[0], what[1])
            )
            conn.commit()
            conn.close()

    class PLC:
        """Minimal MiniCPS-compatible PLC base class."""

        def __init__(self, name, protocol, state, memory=None, disk=None):
            self._name = name
            self._state = SQLiteState(state)
            self.pre_loop()
            self.main_loop()

        def get(self, what):
            return self._state.get(what)

        def set(self, what, value):
            self._state.set(what, value)

        def pre_loop(self, sleep=0.1):
            time.sleep(sleep)

        def main_loop(self, sleep=0.5):
            time.sleep(sleep)


# ================================================
#  State DB configuration
# ================================================

STATE = {
    'name': 'plant',
    'path': DB_PATH
}

# ================================================
#  Network addresses
# ================================================

PLC1_ADDR = os.environ.get('PLC1_ADDR', '192.168.1.20')
PLC2_ADDR = os.environ.get('PLC2_ADDR', '192.168.1.21')
SCADA_ADDR = '192.168.1.10'
ATTACKER_ADDR = '192.168.1.100'
NETMASK = '/24'
MODBUS_PORT = int(os.environ.get('MODBUS_PORT', 502))
PLC2_PORT = int(os.environ.get('PLC2_PORT', MODBUS_PORT))

# ================================================
#  Process tags — (name, plc_id)
#
#  Sensor tags   (physical process writes, PLC2 reads)  plc_id = 2
#  Actuator tags (PLC1 writes, physical process reads)  plc_id = 1
# ================================================

TANK_LEVEL  = ('TANK_LEVEL', 2)
TEMPERATURE = ('TEMPERATURE', 2)
SOUND_LEVEL = ('SOUND_LEVEL', 2)
ULTRASONIC  = ('ULTRASONIC', 2)
MOTION      = ('MOTION', 2)

PUMP_STATE  = ('PUMP_STATE', 1)
VALVE_POS   = ('VALVE_POS', 1)
ALARM_STATE = ('ALARM_STATE', 1)

# Initial values for state DB
INIT_TAGS = {
    TANK_LEVEL:  '500',
    TEMPERATURE: '300',
    SOUND_LEVEL: '100',
    ULTRASONIC:  '50',
    MOTION:      '0',
    PUMP_STATE:  '0',
    VALVE_POS:   '90',
    ALARM_STATE: '0',
}

# ================================================
#  Physical process constants
# ================================================

FILL_RATE  = 5.0   # ADC units per cycle when pump ON
DRAIN_RATE = 2.0   # ADC units per cycle (gravity outflow)
CYCLE_TIME = 0.2   # seconds per simulation step

# ================================================
#  PLC timing
# ================================================

PLC_PERIOD = 0.2   # 200ms scan cycle (matches Arduino firmware)

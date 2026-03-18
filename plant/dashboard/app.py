"""
CPS Water Treatment Plant — Dashboard

Web-based GUI for the plant simulation with:
- Live SVG plant visualization (tank, pump, valve, sensors)
- Real-time sensor data via WebSocket
- SCADA controls (pump toggle, valve slider)
- Attack terminal with output streaming
- Simulation lifecycle management (start/stop)

Usage:
    python3 app.py
    python3 app.py --port 9000
    # Open http://localhost:8888
"""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
import uvicorn

# Paths
DASHBOARD_DIR = Path(__file__).parent
SIMULATION_DIR = DASHBOARD_DIR.parent / "simulation"
ATTACK_SCRIPT = DASHBOARD_DIR.parent / "attack-framework.py"


@asynccontextmanager
async def lifespan(app):
    yield
    await attack_runner.stop()
    await sim_manager.stop()


app = FastAPI(title="CPS Plant Dashboard", lifespan=lifespan)


# ================================================================
#  Simulation Process Manager
# ================================================================

class SimulationManager:
    """Manages the three simulation subprocesses."""

    def __init__(self):
        self.procs: list[asyncio.subprocess.Process] = []
        self.running = False
        self.plc1_port = 5502
        self.plc2_port = 5520

    async def start(self):
        if self.running:
            return {"status": "already_running"}

        # Initialize state DB
        init_script = SIMULATION_DIR / "init.py"
        p = await asyncio.create_subprocess_exec(
            sys.executable, str(init_script),
            cwd=str(SIMULATION_DIR)
        )
        await p.wait()

        # Start physical process
        self.procs.append(await asyncio.create_subprocess_exec(
            sys.executable, str(SIMULATION_DIR / "physical_process.py"),
            cwd=str(SIMULATION_DIR),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        ))
        await asyncio.sleep(1)

        # Start PLC2 on separate port
        env2 = os.environ.copy()
        env2["MODBUS_PORT"] = str(self.plc2_port)
        self.procs.append(await asyncio.create_subprocess_exec(
            sys.executable, str(SIMULATION_DIR / "plc2.py"),
            cwd=str(SIMULATION_DIR),
            env=env2,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        ))
        await asyncio.sleep(2)

        # Start PLC1 — connects to PLC2, serves SCADA on its own port
        env1 = os.environ.copy()
        env1["MODBUS_PORT"] = str(self.plc1_port)
        env1["PLC2_ADDR"] = "127.0.0.1"
        env1["PLC2_PORT"] = str(self.plc2_port)
        self.procs.append(await asyncio.create_subprocess_exec(
            sys.executable, str(SIMULATION_DIR / "plc1.py"),
            cwd=str(SIMULATION_DIR),
            env=env1,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        ))
        await asyncio.sleep(2)

        self.running = True
        return {"status": "started", "plc1_port": self.plc1_port}

    async def stop(self):
        for p in reversed(self.procs):
            try:
                p.terminate()
                await asyncio.wait_for(p.wait(), timeout=3)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    p.kill()
                except ProcessLookupError:
                    pass
        self.procs.clear()
        self.running = False
        return {"status": "stopped"}


sim_manager = SimulationManager()


# ================================================================
#  Attack Runner
# ================================================================

class AttackRunner:
    """Spawns attack scripts and streams output."""

    def __init__(self):
        self.proc: asyncio.subprocess.Process | None = None
        self.attack_name: str | None = None

    async def start(self, attack_name: str, plc_port: int):
        if self.proc and self.proc.returncode is None:
            return {"error": "Attack already running"}

        # Build a small Python snippet that runs the attack
        script = (
            f"import sys; sys.path.insert(0, '{ATTACK_SCRIPT.parent}');\n"
            f"from importlib import import_module;\n"
            f"af = import_module('attack-framework');\n"
            f"fw = af.ICSAttackFramework.__new__(af.ICSAttackFramework);\n"
            f"from pymodbus.client import ModbusTcpClient;\n"
            f"fw.client = ModbusTcpClient('127.0.0.1', port={plc_port});\n"
            f"fw.client.connect();\n"
            f"fw.{attack_name}()\n"
        )

        self.proc = await asyncio.create_subprocess_exec(
            sys.executable, "-u", "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.attack_name = attack_name
        return {"status": "started", "attack": attack_name}

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.proc.kill()
        self.proc = None
        self.attack_name = None
        return {"status": "stopped"}

    async def read_line(self) -> str | None:
        if self.proc and self.proc.stdout:
            try:
                line = await asyncio.wait_for(
                    self.proc.stdout.readline(), timeout=0.5
                )
                if line:
                    return line.decode("utf-8", errors="replace").rstrip()
            except asyncio.TimeoutError:
                pass
        return None


attack_runner = AttackRunner()


# ================================================================
#  Modbus Poller
# ================================================================

async def poll_modbus(port: int) -> dict:
    """Read all registers from PLC1 via Modbus TCP."""
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient("127.0.0.1", port=port)
        if not client.connect():
            return {"connected": False}

        regs = client.read_holding_registers(0, count=6)
        coils = client.read_coils(0, count=1)
        client.close()

        if regs.isError() or coils.isError():
            return {"connected": False}

        tank_level = regs.registers[0]
        return {
            "connected": True,
            "tank_level": tank_level,
            "tank_percent": int(tank_level * 100 / 1023) if tank_level > 0 else 0,
            "valve_position": regs.registers[1],
            "temperature": regs.registers[2],
            "sound_level": regs.registers[3],
            "ultrasonic": regs.registers[4],
            "alarm_state": regs.registers[5],
            "pump_state": int(coils.bits[0]),
        }
    except Exception:
        return {"connected": False}


async def write_modbus(port: int, action: str, address: int, value) -> bool:
    """Write a coil or register to PLC1."""
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient("127.0.0.1", port=port)
        if not client.connect():
            return False
        if action == "write_coil":
            client.write_coil(address, bool(value))
        elif action == "write_register":
            client.write_register(address, int(value))
        client.close()
        return True
    except Exception:
        return False


# ================================================================
#  HTTP Routes
# ================================================================

@app.get("/")
async def index():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.post("/api/simulation/start")
async def start_simulation():
    result = await sim_manager.start()
    return JSONResponse(result)


@app.post("/api/simulation/stop")
async def stop_simulation():
    await attack_runner.stop()
    result = await sim_manager.stop()
    return JSONResponse(result)


@app.get("/api/simulation/status")
async def simulation_status():
    return JSONResponse({"running": sim_manager.running})


# ================================================================
#  WebSocket: Plant Data
# ================================================================

plant_clients: set[WebSocket] = set()


@app.websocket("/ws/plant")
async def ws_plant(ws: WebSocket):
    await ws.accept()
    plant_clients.add(ws)
    try:
        while True:
            # Handle incoming SCADA commands
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=0.15)
                msg = json.loads(raw)
                action = msg.get("action")
                if action in ("write_coil", "write_register"):
                    await write_modbus(
                        sim_manager.plc1_port,
                        action,
                        msg.get("address", 0),
                        msg.get("value", 0),
                    )
            except asyncio.TimeoutError:
                pass

            # Poll and send plant state
            if sim_manager.running:
                data = await poll_modbus(sim_manager.plc1_port)
                await ws.send_text(json.dumps(data))
            else:
                await ws.send_text(json.dumps({"connected": False}))

            await asyncio.sleep(0.2)

    except WebSocketDisconnect:
        pass
    finally:
        plant_clients.discard(ws)


# ================================================================
#  WebSocket: Attack Terminal
# ================================================================

@app.websocket("/ws/terminal")
async def ws_terminal(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            # Check for commands from client
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=0.1)
                msg = json.loads(raw)
                cmd = msg.get("command")

                if cmd == "start":
                    attack = msg.get("attack", "read_state")
                    result = await attack_runner.start(
                        attack, sim_manager.plc1_port
                    )
                    await ws.send_text(json.dumps(result))

                elif cmd == "stop":
                    result = await attack_runner.stop()
                    await ws.send_text(json.dumps(result))

            except asyncio.TimeoutError:
                pass

            # Stream attack output
            line = await attack_runner.read_line()
            if line:
                await ws.send_text(json.dumps({"output": line}))

            await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        pass


# ================================================================
#  Shutdown
# ================================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()
    uvicorn.run(app, host="0.0.0.0", port=args.port)

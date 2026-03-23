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


def api_post(path):
    try:
        req = Request(f"{DASHBOARD_URL}{path}", data=b"", method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except (URLError, Exception):
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
    print("[*] Starting plant simulation via dashboard API ...")
    result = api_post("/api/simulation/start")
    if result and result.get("status") in ("started", "already_running"):
        print(f"[+] Simulation running (PLC1 on port {PLC_PORT})")
        return True
    print(f"[!] Failed to start simulation: {result}")
    return False


def countdown(label, seconds):
    for i in range(seconds, 0, -1):
        print(f"\r    {label} {i}s ...  ", end="", flush=True)
        time.sleep(1)
    print()


def run_attack(attack, framework_path):
    """Spawn attack as subprocess, stream output, kill after duration."""
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

    # 3) Baseline
    print(f"\n[*] Baseline period ({args.baseline}s) — normal traffic only")
    print("    Monitor + tcpdump should be capturing in other panes")
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

        start_time = ts()
        t0 = time.time()
        print(f"  [{start_time}] STARTED")

        run_attack(attack, framework)

        end_time = ts()
        elapsed = time.time() - t0
        print(f"  [{end_time}] STOPPED ({elapsed:.0f}s)")

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

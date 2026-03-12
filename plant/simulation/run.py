"""
Water Treatment Plant Simulation — Main Runner

Starts the full Mininet-based CPS simulation:
  1. Creates the plant network topology
  2. Initializes the state database
  3. Launches physical process, PLC2, PLC1
  4. Drops into Mininet CLI for interaction

Requires root (Mininet needs network namespaces).

Usage:
  sudo python3 run.py              # full Mininet simulation
  sudo python3 run.py --no-mininet # local mode (no network isolation)
"""

import os
import sys
import time
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_mininet():
    """Full simulation with Mininet network isolation."""

    from mininet.net import Mininet
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    from mininet.node import NullController

    from topo import PlantTopo
    from init import init_db

    setLogLevel('info')

    # Initialize state DB
    init_db()

    # Create network (LinuxBridge switch, no OpenFlow controller needed)
    topo = PlantTopo()
    net = Mininet(topo=topo, controller=NullController)
    net.start()

    # Get host references
    plc1 = net.get('plc1')
    plc2 = net.get('plc2')
    scada = net.get('scada')
    attacker = net.get('attacker')

    # Verify connectivity
    print("\n[RUN] Testing network connectivity...")
    net.pingAll()

    # Log directory for PLC output
    log_dir = BASE_DIR
    print("\n[RUN] Logs will be in: {}/*.log".format(log_dir))

    # Start physical process (runs outside network namespace)
    print("[RUN] Starting physical process...")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, 'physical_process.py')],
        stdout=open(os.path.join(log_dir, 'process.log'), 'w'),
        stderr=subprocess.STDOUT
    )
    time.sleep(1)

    # Start PLC2 (sensor node)
    print("[RUN] Starting PLC2 (sensor node)...")
    plc2.cmd(
        'cd {} && {} plc2.py > {}/plc2.log 2>&1 &'.format(
            BASE_DIR, sys.executable, log_dir)
    )
    time.sleep(2)

    # Start PLC1 (process controller)
    print("[RUN] Starting PLC1 (process controller)...")
    plc1.cmd(
        'cd {} && {} plc1.py > {}/plc1.log 2>&1 &'.format(
            BASE_DIR, sys.executable, log_dir)
    )
    time.sleep(3)

    # Print status
    print("\n" + "=" * 50)
    print("  WATER TREATMENT PLANT SIMULATION")
    print("=" * 50)
    print("  PLC 1 (controller):  {} port 502".format(plc1.IP()))
    print("  PLC 2 (sensors):     {} port 502".format(plc2.IP()))
    print("  SCADA:               {}".format(scada.IP()))
    print("  Attacker:            {}".format(attacker.IP()))
    print("=" * 50)
    print()
    print("  Logs:  {}/plc1.log, plc2.log, process.log".format(log_dir))
    print()
    print("  Example commands from Mininet CLI:")
    print("    scada python3 -c \"from pymodbus.client import ModbusTcpClient;c=ModbusTcpClient('192.168.1.20');c.connect();print(c.read_holding_registers(0,count=6).registers)\"")
    print()
    print("    xterm scada     # open terminal on SCADA host")
    print("    xterm attacker  # open terminal on attacker host")
    print("=" * 50)
    print()

    # Drop into CLI
    CLI(net)

    # Cleanup
    proc.terminate()
    net.stop()


def run_local():
    """Simplified local mode without Mininet (no network isolation).

    All processes run on localhost. Useful for quick testing
    when Mininet is not available.
    """

    from init import init_db

    # Initialize state DB
    init_db()

    procs = []

    try:
        # Start physical process
        print("[RUN] Starting physical process...")
        procs.append(subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, 'physical_process.py')]
        ))
        time.sleep(1)

        # Start PLC2
        print("[RUN] Starting PLC2 (sensor node)...")
        procs.append(subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, 'plc2.py')]
        ))
        time.sleep(2)

        # Start PLC1
        print("[RUN] Starting PLC1 (process controller)...")
        procs.append(subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, 'plc1.py')]
        ))

        print()
        print("=" * 50)
        print("  WATER TREATMENT PLANT SIMULATION (LOCAL)")
        print("=" * 50)
        print("  PLC 1 (controller):  127.0.0.1:502")
        print("  PLC 2 (sensors):     127.0.0.1:502")
        print()
        print("  NOTE: Local mode — both PLCs share localhost.")
        print("  PLC2 and PLC1 compete for port 502.")
        print("  For full network isolation use: sudo python3 run.py")
        print("=" * 50)
        print()
        print("Press Ctrl+C to stop...")
        print()

        # Wait for processes
        for p in procs:
            p.wait()

    except KeyboardInterrupt:
        print("\n[RUN] Shutting down...")
        for p in procs:
            p.terminate()


if __name__ == '__main__':

    if os.geteuid() != 0 and '--no-mininet' not in sys.argv:
        print("Mininet requires root. Run with:")
        print("  sudo python3 run.py")
        print()
        print("Or use local mode (no network isolation):")
        print("  python3 run.py --no-mininet")
        sys.exit(1)

    if '--no-mininet' in sys.argv:
        run_local()
    else:
        run_mininet()

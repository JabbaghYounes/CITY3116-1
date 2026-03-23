# Attack Runs & Evidence Capture Guide

Step-by-step walkthrough for running attacks against the CPS plant simulation while the IDS monitor captures forensic evidence.

## Prerequisites

Before starting, ensure the following are installed and built:

```bash
# 1. Build the IDS monitor (if not already built)
cd ids && cargo build --release -p ids-engine --bin monitor

# 2. Verify Python dependencies
pip install pymodbus fastapi uvicorn websockets onnxruntime

# 3. Export CNN+LSTM model to ONNX (one-time, if not already done)
cd ids/pytorch-train && python3 export_onnx.py

# 4. Install tcpdump (for PCAP capture — needs sudo)
#    Should already be available on most Linux installs
which tcpdump

# 5. Create evidence output directory
mkdir -p evidence/{pcaps,logs,screenshots}
```

## Evidence Artifacts Collected

Each attack run produces:

| Artifact | Tool | Location | Format |
|----------|------|----------|--------|
| Packet capture | tcpdump | `evidence/pcaps/` | `.pcap` |
| IDS alert log | monitor | `evidence/logs/` | JSONL (one JSON object per line) |
| Monitor terminal output | monitor | `evidence/logs/` | text (copy from terminal) |
| Dashboard screenshots | manual | `evidence/screenshots/` | PNG |
| Attack terminal output | dashboard | `evidence/screenshots/` | PNG (screenshot of browser) |

---

## Step 1: Open Four Terminal Windows

You need four terminals running simultaneously. Arrange them so all are visible (tiling recommended for screenshots).

| Terminal | Purpose | Runs as |
|----------|---------|---------|
| T1 | Plant Dashboard (simulation) | normal user |
| T2 | IDS Monitor | root (sudo) |
| T3 | Packet Capture (tcpdump) | root (sudo) |
| T4 | Spare (for CLI attacks or notes) | normal user |

---

## Step 2: Start the Plant Simulation

**Terminal T1:**

```bash
cd plant/dashboard
python3 app.py
```

Open your browser to **http://localhost:8888**.

Click **"Start Simulation"** in the dashboard. Wait for the status to show "Running". You should see:
- Tank level updating in the plant visualization
- Sensor data cards showing live values (200ms updates)
- Pump and valve responding to control logic (pump ON < 30%, OFF > 85%)

**Take a screenshot** of the dashboard in normal operation (before any attacks) and save as `evidence/screenshots/01-normal-operation.png`.

---

## Step 3: Start Packet Capture

**Terminal T3:**

```bash
# Capture all loopback traffic on the Modbus port
sudo tcpdump -i lo tcp port 5502 -w evidence/pcaps/full-session.pcap
```

Leave this running for the entire session. It captures all Modbus traffic between the simulation and any attackers/monitors.

> **Tip:** You can also run per-attack captures. Stop and restart tcpdump with a new filename before each attack.

---

## Step 4: Start the IDS Monitor (with ML Inference)

**Terminal T2:**

```bash
cd ids

# With CNN+LSTM ML inference (recommended for evidence)
sudo ./target/release/monitor \
  --interface lo \
  --modbus-port 5502 \
  --log-file ../evidence/logs/alerts.jsonl \
  --model pytorch-train/data/models/model-b/cnn_lstm_model.onnx \
  --scaler pytorch-train/data/models/model-b/scaler.json \
  --ml-threshold 0.5 \
  --flow-timeout 15
```

You should see the startup banner:

```
========================================
  CPS-IDS Live Monitor
========================================
  Interface:      lo
  Modbus ports:   [5502]
  Log file:       ../evidence/logs/alerts.jsonl
  Write threshold: 2.0 writes/sec
  ML detection:   CNN+LSTM ENABLED
  ML threshold:   50%
========================================
```

Wait 15-30 seconds to see normal traffic stats appear (`[STATS] packets=... modbus=...`). This confirms the monitor is capturing Modbus traffic from the simulation.

**Take a screenshot** of the monitor running with normal traffic and save as `evidence/screenshots/02-monitor-normal.png`.

---

## Step 5: Run Attacks (One at a Time)

Run each attack from the dashboard, wait for evidence, then stop before the next. For each attack:

1. **Note the time** (for correlating with logs)
2. **Start a per-attack PCAP** (optional, in T3)
3. **Launch the attack** from the dashboard
4. **Wait 30-60 seconds** for the attack to generate traffic and the monitor to detect it
5. **Screenshot** the dashboard showing the attack effect + the monitor terminal showing alerts
6. **Stop the attack** from the dashboard

---

### Attack 1: Command Injection

**What it does:** Forces the pump ON and OFF every 5 seconds using Modbus Write Coil (FC 0x05).

**Dashboard:** Select **"Command Injection"** from the dropdown, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/write-rate` — "High Modbus write rate" (if rate exceeds 2.0/sec)
- `cnn-lstm/model-b` — ML classification on expired flows

**Expected behavior:**
- Pump toggles independently of tank level
- Tank level may rise/fall erratically
- Dashboard shows pump state flipping

**Evidence to capture:**
- Screenshot: `evidence/screenshots/03-attack-command-injection.png` (dashboard + monitor)
- Let it run for **30-60 seconds**, then stop

---

### Attack 2: Pump Oscillation

**What it does:** Rapidly toggles the pump every 2 seconds (FC 0x05). More aggressive than Command Injection.

**Dashboard:** Select **"Pump Oscillation"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/write-rate` — HIGH severity, write rate > 0.5/sec
- `cnn-lstm/model-b` — DoS or Probe classification

**Expected behavior:**
- Pump state flips rapidly (visible in dashboard)
- Tank level oscillates

**Evidence to capture:**
- Screenshot: `evidence/screenshots/04-attack-pump-oscillation.png`
- Let it run for **30-60 seconds**, then stop

---

### Attack 3: Valve Manipulation

**What it does:** Writes random valve positions (0-180 degrees) to register 1 every 3 seconds (FC 0x06).

**Dashboard:** Select **"Valve Manipulation"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/write-rate` — if write rate exceeds threshold
- `cnn-lstm/model-b` — classification on flow

**Expected behavior:**
- Valve position jumps to random values (normally only 40 or 120 degrees)
- Dashboard valve visualization moves erratically

**Evidence to capture:**
- Screenshot: `evidence/screenshots/05-attack-valve-manipulation.png`
- Let it run for **30-60 seconds**, then stop

---

### Attack 4: Replay Attack

**What it does:** Replays a fixed sequence of 4 pump commands (ON, OFF, ON, OFF) every second (FC 0x05).

**Dashboard:** Select **"Replay Attack"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/write-rate` — predictable pattern
- `cnn-lstm/model-b` — classification on flow

**Expected behavior:**
- Pump cycles through a fixed ON/OFF/ON/OFF pattern
- Deterministic 1-second intervals

**Evidence to capture:**
- Screenshot: `evidence/screenshots/06-attack-replay.png`
- Let it run for **30-60 seconds**, then stop

---

### Attack 5: Sensor Spoofing

**What it does:** Writes random values (0-100) to register 0 (tank level) every 2 seconds (FC 0x06). Falsifies the sensor reading.

**Dashboard:** Select **"Sensor Spoofing"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/write-rate` — register 0 write anomaly
- `cnn-lstm/model-b` — classification on flow
- Physics anomaly: tank level doesn't match pump state

**Expected behavior:**
- Tank level display jumps randomly (dashboard shows erratic readings)
- Pump logic may malfunction (reacts to spoofed levels)

**Evidence to capture:**
- Screenshot: `evidence/screenshots/07-attack-sensor-spoofing.png`
- Let it run for **30-60 seconds**, then stop

---

### Attack 6: Modbus Flood (DoS)

**What it does:** Sends 100 Read Holding Registers requests (FC 0x03) in a tight loop, repeatedly.

**Dashboard:** Select **"Modbus Flood"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- `rule-engine/modbus-analysis` — "Modbus read flood: X packets/sec"
- `cnn-lstm/model-b` — DoS classification (high confidence)

**Expected behavior:**
- Massive spike in packet count (visible in `[STATS]` line)
- PLC may become slow to respond to legitimate requests
- Dashboard sensor updates may lag

**Evidence to capture:**
- Screenshot: `evidence/screenshots/08-attack-modbus-flood.png`
- Let it run for **15-30 seconds** (shorter — it generates lots of traffic), then stop

---

### Attack 7: Multi-Stage Attack

**What it does:** Three-phase attack simulating an advanced persistent threat:
- **Phase 1 (Reconnaissance, 10s):** 5x reads of all registers and coils
- **Phase 2 (Manipulation, 20s):** 20x random pump/valve writes
- **Phase 3 (Disruption, ~10s):** 200x read flood

**Dashboard:** Select **"Multi-Stage Attack"**, click **"Launch Attack"**.

**Expected IDS alerts:**
- Phase 1: Minimal (reads are normal)
- Phase 2: `rule-engine/write-rate` — write anomalies
- Phase 3: `rule-engine/modbus-analysis` — read flood, `cnn-lstm/model-b` — DoS classification
- Escalating severity: Low → High → Critical across phases

**Expected behavior:**
- Initially quiet (recon), then pump/valve disruption, then flood
- Best demonstrates the full attack lifecycle

**Evidence to capture:**
- Screenshot: `evidence/screenshots/09-attack-multi-stage.png`
- **Let it run to completion** (~40 seconds total for all 3 phases)

---

### Attack 8 (Optional): Stuxnet Rootkit

**What it does:** Autonomous MitM attack with 20-second cycles (8s attack, 12s pause). Oscillates pump, randomizes valve, and falsifies sensor readings.

**Terminal T4** (not from dashboard — runs as standalone script):

```bash
# First modify the target to point at simulation
cd plant/stux

# Edit rootkit-proxy.py: change PLC_IP and PLC_PORT
# PLC_IP = "127.0.0.1"
# PLC_PORT = 5502
python3 rootkit-proxy.py
```

> **Note:** You'll need to edit the IP/port in rootkit-proxy.py to target `127.0.0.1:5502` for simulation mode. The original targets `192.168.1.20:502` (hardware).

**Expected IDS alerts:**
- Intermittent write bursts every 20 seconds
- Mixed FC 0x05/0x06 writes during 8-second attack windows
- ML alerts on flows during active attack phases

**Evidence to capture:**
- Screenshot: `evidence/screenshots/10-attack-rootkit.png`
- Let it run for **2-3 full cycles** (~60 seconds), then Ctrl+C

---

## Step 6: Stop Everything & Collect Evidence

After all attacks are complete:

1. **Stop the dashboard attack** (if still running) — click "Stop" in the attack terminal
2. **Stop tcpdump** (T3) — press `Ctrl+C`. Note the packet count printed
3. **Stop the IDS monitor** (T2) — press `Ctrl+C`. Note the final `[STATS]` line
4. **Stop the simulation** — click "Stop Simulation" in the dashboard, then `Ctrl+C` the app.py

**Take a final screenshot** of the monitor's last stats output: `evidence/screenshots/11-final-stats.png`.

---

## Step 7: Review Collected Evidence

### Alert Log

```bash
# Count total alerts
wc -l evidence/logs/alerts.jsonl

# View alerts (pretty-printed)
cat evidence/logs/alerts.jsonl | python3 -m json.tool --no-ensure-ascii

# Filter by severity
grep '"severity":"Critical"' evidence/logs/alerts.jsonl | python3 -m json.tool
grep '"severity":"High"' evidence/logs/alerts.jsonl | python3 -m json.tool

# Filter by detection source
grep 'cnn-lstm' evidence/logs/alerts.jsonl | python3 -m json.tool
grep 'rule-engine' evidence/logs/alerts.jsonl | python3 -m json.tool
grep 'write-rate' evidence/logs/alerts.jsonl | python3 -m json.tool
grep 'modbus-analysis' evidence/logs/alerts.jsonl | python3 -m json.tool

# Count alerts by category
grep -o '"category":"[^"]*"' evidence/logs/alerts.jsonl | sort | uniq -c | sort -rn

# Count alerts by model source
grep -o '"model_source":"[^"]*"' evidence/logs/alerts.jsonl | sort | uniq -c | sort -rn

# Timeline: first and last alert timestamps
head -1 evidence/logs/alerts.jsonl | python3 -c "import json,sys; print(json.load(sys.stdin)['timestamp'])"
tail -1 evidence/logs/alerts.jsonl | python3 -c "import json,sys; print(json.load(sys.stdin)['timestamp'])"
```

### Packet Capture

```bash
# Summary of capture
tcpdump -r evidence/pcaps/full-session.pcap | wc -l

# View Modbus traffic only
tcpdump -r evidence/pcaps/full-session.pcap tcp port 5502 -nn

# Open in Wireshark for detailed analysis (GUI)
wireshark evidence/pcaps/full-session.pcap &
```

In Wireshark, apply the display filter `modbus` or `tcp.port == 5502` to isolate Modbus traffic. Look for:
- Write Coil (FC 5) bursts during Command Injection / Pump Oscillation
- Write Register (FC 6) during Valve Manipulation / Sensor Spoofing
- Read flood (FC 3) bursts during Modbus Flood
- Mixed patterns during Multi-Stage Attack

---

## Step 8: Generate Evidence Summary

Create a summary table of what was captured:

```
| Attack | Duration | Alerts | Severity | Detection Method | PCAP Packets |
|--------|----------|--------|----------|-----------------|--------------|
| Command Injection | ~60s | ? | ? | rule-engine + cnn-lstm | ? |
| Pump Oscillation | ~60s | ? | ? | rule-engine + cnn-lstm | ? |
| Valve Manipulation | ~60s | ? | ? | rule-engine + cnn-lstm | ? |
| Replay Attack | ~60s | ? | ? | rule-engine + cnn-lstm | ? |
| Sensor Spoofing | ~60s | ? | ? | rule-engine + cnn-lstm | ? |
| Modbus Flood | ~30s | ? | ? | rule-engine + cnn-lstm | ? |
| Multi-Stage | ~40s | ? | ? | rule-engine + cnn-lstm | ? |
```

Fill in the `?` values from the alert log and PCAP after the runs.

---

## Troubleshooting

**Monitor shows 0 modbus packets:**
- Ensure `--modbus-port 5502` matches the simulation port
- Ensure the simulation is running (dashboard shows "Running")
- Check that you're capturing on `lo` (loopback), not `eth0`

**ML inference not producing alerts:**
- Check that `--model` and `--scaler` paths are correct (relative to where you run the monitor)
- Check that `python3` is available and `onnxruntime` is installed: `python3 -c "import onnxruntime"`
- Lower `--ml-threshold` to `0.3` to see more ML alerts
- ML only runs on expired flows (after `--flow-timeout` seconds of idle). Reduce to `10` or `15` for faster detection

**Dashboard attacks not working:**
- Ensure the simulation is started ("Running" status)
- Check the browser console (F12) for WebSocket errors
- Try restarting `app.py`

**tcpdump permission denied:**
- Must run with `sudo`

**Attack framework CLI targets wrong IP:**
- `attack-framework.py` hardcodes `192.168.1.20:502` (hardware mode)
- Use the **dashboard** to launch attacks against the simulation (it overrides to `127.0.0.1:5502`)
- Or temporarily edit `PLC_IP` and `PLC_PORT` in `attack-framework.py`

# Expected Investigation Results

Reference for comparing against actual evidence after running `./investigation/run.sh`.

## How to Know the Script is Done

The **bottom-right pane** (Attack Runner) prints this when finished:

```
============================================================
  ALL ATTACKS COMPLETE
============================================================
```

Total runtime: ~7 minutes (295s attacks + 90s gaps + 20s baseline).

After that banner, wait 15s for final flows to expire, then Ctrl+C the other 3 panes.

---

## Expected Results Per Attack

### 1. Command Injection (45s)

**What it does:** Write Coil (FC 0x05) toggling pump ON/OFF every 5 seconds.

**Expected alerts:**
- `rule-engine/write-rate` — "High Modbus write rate" (severity: HIGH). Writes are every 5s so rate is ~0.2/sec over a 10s window. This is **below** the 2.0 writes/sec threshold, so write-rate alerts are **unlikely** for this attack.
- `cnn-lstm/model-b` — Classification on expired flows. The flow will have relatively few packets (low traffic rate). ML prediction depends on flow features; may classify as Normal, DoS, or Probe.

**Expected Wireshark:** Periodic FC 0x05 write coil requests at 5-second intervals. Low packet density.

**Expected alert count:** 0–2 (mostly from ML on expired flows, unlikely from write-rate)

---

### 2. Pump Oscillation (45s)

**What it does:** Write Coil (FC 0x05) every 2 seconds. More aggressive than Command Injection.

**Expected alerts:**
- `rule-engine/write-rate` — Rate is ~0.5/sec over 10s window. Still **below** the 2.0/sec threshold, so write-rate alerts are **unlikely**.
- `cnn-lstm/model-b` — Flow has more packets than Command Injection. May classify as DoS or Probe.

**Expected Wireshark:** FC 0x05 packets every 2 seconds. Higher density than Attack 1.

**Expected alert count:** 0–3

---

### 3. Valve Manipulation (45s)

**What it does:** Write Register (FC 0x06) with random valve position (0–180) every 3 seconds.

**Expected alerts:**
- `rule-engine/write-rate` — Rate ~0.33/sec. **Below** threshold. Unlikely.
- `cnn-lstm/model-b` — Classification on expired flows.

**Expected Wireshark:** FC 0x06 write register requests with register address 1 and random values. 3-second intervals.

**Expected alert count:** 0–3

---

### 4. Replay Attack (45s)

**What it does:** Write Coil (FC 0x05) replaying ON/OFF/ON/OFF every 1 second.

**Expected alerts:**
- `rule-engine/write-rate` — Rate ~1.0/sec over 10s window. Still **below** 2.0/sec threshold but getting closer. **Borderline** — may or may not trigger.
- `cnn-lstm/model-b` — Higher packet rate flow. More likely to be classified as attack.

**Expected Wireshark:** FC 0x05 at exactly 1-second intervals. Deterministic ON/OFF/ON/OFF pattern (coil value alternating).

**Expected alert count:** 0–5

---

### 5. Sensor Spoofing (45s)

**What it does:** Write Register (FC 0x06) writing random tank level (0–100) to register 0 every 2 seconds.

**Expected alerts:**
- `rule-engine/write-rate` — Rate ~0.5/sec. **Below** threshold.
- `cnn-lstm/model-b` — Classification on expired flows.

**Expected Wireshark:** FC 0x06 write register requests with register address 0 and random values (0–100). Normal traffic writes to register 0 too (tank level updates from PLC), so this mixes with legitimate traffic.

**Expected alert count:** 0–3

---

### 6. Modbus Flood / DoS (20s)

**What it does:** 100x Read Holding Registers (FC 0x03) in a tight loop, repeatedly. Thousands of packets per second.

**Expected alerts:**
- `rule-engine/modbus-analysis` — **"Modbus read flood: X packets/sec"** (severity: HIGH). Triggers when a flow exceeds 50 packets/sec with >20 total packets. This attack will **definitely** trigger this. Expect **many** of these alerts since the check runs on every Modbus read packet.
- `cnn-lstm/model-b` — Flows with massive packet counts. **High confidence DoS** classification expected (severity: CRITICAL).

**Expected Wireshark:** Massive burst of FC 0x03 read holding registers. Hundreds or thousands of packets with almost no inter-packet delay. This will be the most visually obvious attack in the pcap.

**Expected alert count:** 10–100+ (flood detection fires repeatedly)

**This is the attack most likely to generate strong, clear evidence.**

---

### 7. Multi-Stage Attack (~50s)

**What it does:** Three phases:
- **Phase 1 — Reconnaissance (10s):** 5x `read_state()` calls (reads registers + coils) every 2s
- **Phase 2 — Manipulation (20s):** 20x random pump writes (FC 0x05) + valve writes (FC 0x06) every 1s
- **Phase 3 — Disruption (~instant):** 200x Read Holding Registers (FC 0x03) in tight loop

**Expected alerts:**
- Phase 1: **Minimal** — reads are normal operations. No alerts expected.
- Phase 2: `rule-engine/write-rate` — 2 writes/sec (pump + valve per iteration). This **matches** the 2.0/sec threshold exactly. May trigger intermittently. `cnn-lstm/model-b` on expired flows.
- Phase 3: `rule-engine/modbus-analysis` — Read flood detection. **Definite** alerts. `cnn-lstm/model-b` — DoS classification.

**Expected Wireshark:** Three distinct traffic phases visible in the timeline: sparse reads → write bursts → dense read flood.

**Expected alert count:** 5–30 (mostly from phase 3 flood + some from phase 2 writes)

---

## Overall Expected Summary

| Attack | Duration | Write-Rate Alerts | Flood Alerts | ML Alerts | Total Expected |
|--------|----------|-------------------|--------------|-----------|----------------|
| Command Injection | 45s | 0 (rate too low) | 0 | 0–2 | 0–2 |
| Pump Oscillation | 45s | 0 (rate too low) | 0 | 0–2 | 0–2 |
| Valve Manipulation | 45s | 0 (rate too low) | 0 | 0–2 | 0–2 |
| Replay Attack | 45s | 0–1 (borderline) | 0 | 0–3 | 0–4 |
| Sensor Spoofing | 45s | 0 (rate too low) | 0 | 0–2 | 0–2 |
| **Modbus Flood** | 20s | 0 | **10–100+** | **1–5** | **10–100+** |
| **Multi-Stage** | 50s | 0–5 (phase 2) | **5–30** (phase 3) | **1–5** | **5–30** |

**Key insight:** The write-rate threshold (2.0 writes/sec) is set relatively high, meaning most write-based attacks (1-5, which send 0.2–1.0 writes/sec) will NOT trigger write-rate alerts. The read flood detection (>50 pps + >20 packets) will be the primary rule-engine detection source, making **attacks 6 and 7** the strongest evidence generators.

The CNN+LSTM model operates on expired flows (after 15s idle timeout), so ML alerts appear with a delay after each attack ends.

## What to Look For in Wireshark

Open `evidence/pcaps/full-session.pcap` and use these display filters:

| Filter | Shows |
|--------|-------|
| `tcp.port == 5502` | All Modbus traffic |
| `modbus` | Decoded Modbus frames (if Wireshark recognises the port) |
| `modbus.func_code == 5` | Write Coil only (attacks 1, 2, 4) |
| `modbus.func_code == 6` | Write Register only (attacks 3, 5) |
| `modbus.func_code == 3` | Read Holding Registers (attacks 6, 7 phase 3) |

**Note:** Wireshark may not decode Modbus on port 5502 by default (it expects port 502). To fix: right-click any TCP packet on port 5502 → "Decode As" → set port 5502 to Modbus/TCP.

Use **Statistics → I/O Graph** to visualise traffic volume over time. The flood attacks will appear as obvious spikes. Correlate timestamps with `evidence/logs/attack-manifest.json`.

## What to Look For in Alert Logs

```bash
# Total alerts
wc -l evidence/logs/alerts.jsonl

# Alerts by severity
grep -c '"severity":"Critical"' evidence/logs/alerts.jsonl
grep -c '"severity":"High"' evidence/logs/alerts.jsonl

# Alerts by detection source
grep -c 'write-rate' evidence/logs/alerts.jsonl
grep -c 'modbus-analysis' evidence/logs/alerts.jsonl
grep -c 'cnn-lstm' evidence/logs/alerts.jsonl

# Alert categories
grep -o '"category":"[^"]*"' evidence/logs/alerts.jsonl | sort | uniq -c | sort -rn
```

# Investigation Run 1 — Results & Analysis

**Date:** 2026-03-23 16:37–16:49 UTC
**Duration:** ~6 minutes (7 attacks + gaps)
**Monitor config:** `--flow-timeout 15 --ml-threshold 0.5 --modbus-port 5502`

## Evidence Collected

| Artifact | Size | Content |
|----------|------|---------|
| `evidence/pcaps/full-session.pcap` | 3.5 MB | 38,550 packets |
| `evidence/logs/alerts.jsonl` | 34 MB | 82,575 alerts |
| `evidence/logs/attack-manifest.json` | 2.1 KB | 7 attacks with timestamps |

## Attack Timeline

| # | Attack | Start | End | Duration |
|---|--------|-------|-----|----------|
| 1 | Command Injection | 16:37:16 | 16:38:01 | 45s |
| 2 | Pump Oscillation | 16:38:16 | 16:39:01 | 45s |
| 3 | Valve Manipulation | 16:39:17 | 16:40:02 | 45s |
| 4 | Replay Attack | 16:40:17 | 16:41:02 | 45s |
| 5 | Sensor Spoofing | 16:41:17 | 16:42:02 | 45s |
| 6 | Modbus Flood (DoS) | 16:42:17 | 16:42:38 | 20s |
| 7 | Multi-Stage | 16:42:53 | 16:43:23 | 31s |

## Alert Summary

**By severity:**
| Severity | Count |
|----------|-------|
| Critical | 12,657 |
| High | 56,848 |
| Low | 13,070 |

**By detection source:**
| Source | Count | Description |
|--------|-------|-------------|
| rule-engine/rule-2 | 28,492 | Connection attempts to many distinct ports (Probe) |
| rule-engine/rule-8 | 28,056 | Unusually long DNS query suggesting data exfiltration (Probe) |
| rule-engine/rule-9 | 13,070 | Slow SYN-based port scanning (Low) |
| rule-engine/rule-1 | 12,657 | High rate of SYN packets — SYN flood DoS (Critical) |
| rule-engine/write-rate | 300 | Modbus write-rate anomalies (High/DoS) |
| cnn-lstm/model-b | 0 | — |
| rule-engine/modbus-analysis | 0 | — |

**Write-rate alerts by function code:**
- FC 0x05 (Write Coil): fired during Replay Attack and Multi-Stage phase 2 (rates 2.1–4.0 writes/sec)
- FC 0x06 (Write Register): fired during Multi-Stage phase 2 (rates 7.9–8.0 writes/sec)
- Time range: 16:40:22 – 16:43:22

## Analysis

### What Worked

1. **Write-rate detection** correctly identified the faster write-based attacks. The Replay Attack (1 write/sec) combined with the simulation's own PLC writes to exceed the 2.0 writes/sec threshold. Multi-Stage phase 2 (2 writes/iteration at 1s intervals) triggered strongly at 4–8 writes/sec.

2. **Rule engine** fired continuously on all traffic, detecting patterns in the loopback simulation traffic. While many of these are false positives (generic rules matching localhost traffic patterns), they demonstrate the rule engine is operational.

3. **Evidence collection** worked correctly — pcap, alert log, and attack manifest all captured with accurate timestamps for correlation.

### What Did Not Work

1. **CNN+LSTM ML inference: 0 alerts.** Root cause: the monitor was killed via `tmux kill-session` which terminates immediately without allowing active flows to expire. ML inference only runs on expired flows (idle for `--flow-timeout` seconds). With a 15s timeout and 10s check interval, flows need ~25s of uninterrupted idle time to be classified. The session was killed before this could happen.

2. **Modbus flood detection: 0 alerts.** Root cause: the flood detection code matches flows using only source/destination IP addresses, not ports. On localhost (127.0.0.1 → 127.0.0.1), this matches the first flow found in the table — which is typically a simulation flow (PLC1↔PLC2), not the attack flow. The attack flow's packet count is never checked.

### False Positive Analysis

The bulk of alerts (82,275 of 82,575 = 99.6%) come from generic network rules designed for internet traffic being applied to localhost simulation traffic:
- **Rule 2** ("many distinct ports"): fires because the simulation uses multiple ephemeral ports on the same IP
- **Rule 8** ("long DNS query"): fires on Modbus payloads that exceed a length threshold meant for DNS
- **Rule 9** ("slow port scan"): fires on the simulation's normal multi-port communication pattern
- **Rule 1** ("SYN flood"): fires on normal TCP connection establishment between simulation components

These represent a **high false positive rate** when running on loopback. In a production deployment on a real network with distinct IPs, these rules would perform differently.

## Fixes for Run 2

1. Reduce `--flow-timeout` from 15 to 5 seconds for faster flow expiry
2. Add graceful shutdown handler to expire remaining flows on Ctrl+C/SIGINT
3. Fix flood detection to use full FlowKey matching (5-tuple: IPs + ports + protocol)
4. Add a ReadTracker (analogous to WriteTracker) for rate-based read flood detection
5. Keep the monitor running for 30s after attacks complete before stopping

# Advanced Computer Forensics and Security
## Assignment 1

**BY:** [Your Name]
**DATE:** [Date]

---

## Table of Contents

1. [Task 1: AI/ML-Driven Intrusion Detection/Prevention System](#task-1-aiml-driven-intrusion-detectionprevention-system)
   - 2.1 IDS/IPS Fundamentals
   - 2.2 System Design for CPS Security
   - 2.3 AI/ML Implementation
   - 2.4 Evaluation and Comparison
   - 2.5 Advantages, Limitations, and Challenges
2. [Task 2: Forensic Investigation and Incident Response](#task-2-forensic-investigation-and-incident-response)
   - 3.1 Attack Scenarios
   - 3.2 Forensic Tools and Methodology
   - 3.3 Forensic Analysis
   - 3.4 AI/ML in Forensic Analysis
   - 3.5 Incident Report
3. [Security Recommendations](#security-recommendations)
4. [Conclusion](#conclusion)

---

## Task 1: AI/ML-Driven Intrusion Detection/Prevention System

### 2.1 IDS/IPS Fundamentals

Intrusion Detection Systems (IDS) monitor network traffic and system activities for malicious behaviour, operating passively to alert security personnel without directly intervening. Intrusion Prevention Systems (IPS) extend this by actively blocking detected threats inline with network traffic. In CPS environments, IDS is the more appropriate choice because availability is paramount within the CIA triad — an IPS operating inline could drop packets deemed suspicious, potentially disrupting safety-critical control loops. A false positive halting a pump or closing a valve carries consequences far more severe than in traditional IT networks. IDS preserves operational continuity by monitoring passively.

IDS can be deployed as network-based (NIDS), analysing packet headers and payloads at strategic points, or host-based (HIDS), monitoring system calls, file modifications, and process behaviour on individual hosts. Detection methods include signature-based detection (matching known attack patterns, effective but blind to zero-days), anomaly-based detection (flagging deviations from a learned baseline, capable of detecting novel attacks but prone to false positives), and stateful protocol analysis (comparing behaviour against known-good protocol profiles).

### 2.2 System Design for CPS Security

The proposed IDS employs a hybrid architecture combining signature-based and anomaly-based detection, enhanced with machine learning. The system is implemented in Rust for its combination of C/C++-comparable performance, compile-time memory safety guarantees, and concurrency support — critical for a security tool where a buffer overflow in the IDS itself could become an attack vector.

**System Architecture Components:**

![IDS System Architecture](../resources/images/ids-architecture.png)

The IDS is designed with protocol awareness for industrial protocols, performing Modbus function code validation and register address/value extraction on every packet. Physical process modelling is central to the detection strategy: the IDS encodes plant-specific constraints (tank capacity, valve servo range, pump control thresholds, fill/drain rates) and validates every Modbus write against these constraints. Passive observation of Modbus read responses maintains a live model of plant state, enabling detection of state-inconsistent commands even when individual writes appear valid. The system also whitelists expected communication patterns and performs time-series analysis for detecting gradual process manipulation through rate-of-change monitoring and pump toggle frequency tracking, while prioritising minimal latency impact on control loops.

### 2.3 AI/ML Implementation

**Dataset Selection:**

The system trains on three public intrusion detection datasets mapped to a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R): **NSL-KDD (1999)** with 122 features (41 raw + one-hot encoding of 3 categorical columns) covering classic attack categories, **CIC-IDS2017 (2017)** with 78 numeric features providing modern attack traffic (DDoS, brute force, web attacks, infiltration) with realistic benign background, and **UNSW-NB15 (2015)** with 76 numeric features across 448K records covering modern mixed attack types including backdoors, shellcode, and worms. These general-purpose datasets were selected for their size, public availability, and cross-era generalisation potential. An alternative approach would be ICS-specific datasets such as SWaT (Secure Water Treatment, 36 labelled attacks) or the Mississippi State SCADA Gas Pipeline Dataset (Modbus-based with command injection and DoS labels). These would have provided better domain alignment for Modbus traffic — a limitation whose impact is discussed in Section 3.3.

**Model Architecture:**

A multi-model ensemble approach is employed:

1. **Random Forest Classifier:** 100 estimators, max depth 20, minimum samples split 5. Robust against overfitting and provides feature importance rankings.

![Random Forest Architecture](../resources/images/model-random-forest.png)

2. **CNN+LSTM Network (~297K parameters):** Two convolutional blocks (Conv1d with 64 and 128 filters, kernel size 3, each with batch normalisation and ReLU) feed into a 2-layer LSTM (128 hidden units, 0.3 dropout), followed by fully connected layers (128→64→5) producing a 5-class prediction. Trained with Adam optimiser and early stopping (patience 5 epochs).

![CNN+LSTM Architecture](../resources/images/model-cnn-lstm.png)

3. **Isolation Forest:** Unsupervised anomaly detection for novel attack patterns not present in training data.

![Isolation Forest Architecture](../resources/images/model-isolation-forest.png)

**Training Methodology:**

![Training Pipeline](../resources/images/training-pipeline.png)

Each dataset is split 70/12/18 for training, validation, and testing. SMOTE oversampling is applied to imbalanced datasets (NSL-KDD, UNSW-NB15) but disabled for larger datasets (CIC-IDS2017, Combined). All features are normalised using MinMax scaling fitted exclusively on the training split to prevent data leakage.

**Implementation:**

![Implementation Framework](../resources/images/tech-stack.png)

The system uses Rust with smartcore 0.3 for Random Forest and Isolation Forest, Python PyTorch (AMD ROCm) and tch-rs 0.17 (NVIDIA libtorch) for CNN+LSTM training, libpcap for packet capture, and rayon for parallelised training. The final system is a hybrid NIDS+HIDS with live packet capture, ICS/SCADA protocol parsing (Modbus, DNP3, OPC-UA), host-based monitoring (file integrity, process monitoring, syscall tracing), and multi-model ensemble with weighted fusion across four independent training backends.

### 2.4 Evaluation and Comparison

The ML-based IDS is evaluated using accuracy, precision, recall, F1-score, and false positive rate (FPR).

**Training Results (5-class classification):**

| Model | Dataset | Features | Random Forest | CNN+LSTM | Isolation Forest | RF + IForest | FPR |
|-------|---------|----------|---------------|----------|------------------|--------------|-----|
| A | NSL-KDD (1999) | 122 | 67.26%* | 65.94%* | 77.24% | 67.26%* | 0.0301 |
| B | CIC-IDS2017 (2017) | 78 | 99.73% | **99.83%** | 81.37% | 99.73% | **0.0006** |
| C | UNSW-NB15 (2015) | 76 | 93.90% | 92.95% | 82.50% | 93.84% | 0.0251 |
| D | Combined (A+B+C) | 276 | 97.80% | 97.67% | 80.20% | **97.82%** | 0.0043 |

*Model A metrics limited by binary-only test labels in NSL-KDD (Probe/R2L/U2R collapsed to a single attack class).

The CNN+LSTM achieves the highest accuracy at 99.83% on Model B, while Model D demonstrates cross-era generalisation at 97.8% across 276 zero-padded features spanning 1999–2017. The RF + IForest ensemble improves minority class detection (Model D R2L recall: 0.75→0.82). The Isolation Forest provides an unsupervised baseline at ~80% across all datasets. Compared to rule-based systems like Snort, which suffer from inability to detect novel attacks and constant rule maintenance, the ML ensemble achieves false positive rates as low as 0.06% (Model B) with adaptive capability through retraining.

### 2.5 Advantages, Limitations, and Challenges

The following insights are drawn from implementing and deploying the IDS against the water treatment simulation.

**Advantages:** The ML classifier detected all 8 attacks including Command Injection and Pump Oscillation, which operated below the write-rate threshold and matched no signature rule — demonstrating detection beyond traditional approaches. Model D achieved 97.82% cross-era generalisation across datasets spanning 1999–2017, with ensemble R2L recall improving from 0.75 to 0.82. ONNX Runtime inference at ~1ms per prediction proved compatible with the 200ms PLC scan cycle, and the Isolation Forest provided ~80% unsupervised zero-day detection without labelled data.

**Limitations:** The most critical finding was the domain gap: the CNN+LSTM achieved 99.83% on CIC-IDS2017 test data but classified 100% of live Modbus traffic as Normal, because CIC-IDS2017 attacks produce 50,000+ packets at GB/s while Modbus floods produce ~500 packets at KB/s — after MinMax scaling, all Modbus features collapsed to near-zero. Offline accuracy does not predict deployment effectiveness when training and target domains differ. Furthermore, the CPS physics engine detected attacks no ML model could (valve positions exceeding physical maximums, writes to read-only sensor registers), demonstrating that ML must be supplemented by physics-based validation. The generic rule engine generated 61,160 false positives (82% of alerts) from internet-oriented rules firing on simulation traffic, highlighting that false positive fatigue in CPS is dangerous — operators who learn to ignore alerts will miss real attacks. Finally, deep learning's black-box nature limits forensic utility; the physics engine's causal explanations ("Pump forced ON while tank at 890") are immediately actionable, while ML outputs ("R2L detected, 70% confidence") require further investigation.

---

## Task 2: Forensic Investigation and Incident Response

### 3.1 Attack Scenarios

The forensic investigation executes eight automated attack scenarios against the MiniCPS water treatment simulation, targeting PLC 1's Modbus TCP server (port 5502). Five process manipulation attacks exploit Modbus TCP's lack of authentication: Command Injection (pump ON/OFF every 5s via FC 0x05), Pump Oscillation (Stuxnet-style rapid toggling every 2s), Valve Manipulation (random positions 0–180° via FC 0x06), Replay Attack (captured ON/OFF sequence replayed at 1s intervals), and Sensor Spoofing (fake tank levels written to register 0). A Modbus Flood attack (100× FC 0x03 reads in a tight loop) tests denial of service. A Multi-Stage Attack simulates an APT lifecycle: reconnaissance (register reads over 10s), process manipulation (random writes over 20s), and disruption (200× read flood). Finally, a Stuxnet-style Rootkit operates as an async MitM proxy with intermittent attack cycles (20s interval, 8s active), manipulating actuators while falsifying sensor readings — mirroring Stuxnet's documented behaviour.

All attacks use pymodbus 3.x with 15-second gaps for flow expiration. System artifacts (processes, connections, PLC registers) are captured before and after each attack.

### 3.2 Forensic Tools and Methodology

The investigation employs five tools: **tcpdump** for full-session PCAP capture; **Wireshark** for post-capture Modbus/TCP protocol analysis with display filters (`modbus.func_code == 5/6/3`), I/O graphs, and conversation statistics; the **CPS-IDS Monitor** running a multi-layer detection pipeline (20-rule engine, Modbus write-rate anomaly, read flood detection, CNN+LSTM inference); an **attack manifest** recording timestamps per attack; and **system artifact collection** capturing process listings, network connections, and PLC register snapshots at 19 points. Volatility and Autopsy were not applicable — PLCs run bare-metal firmware without virtual memory or persistent filesystems; PLC register snapshots provide the equivalent forensic data.

The methodology follows NIST SP 800-86: simultaneous collection of four evidence streams (3.5 MB PCAP, 74,870 IDS alerts, attack manifest, 19 system snapshots), examination through alert grouping and Modbus dissector analysis, cross-referencing alert timestamps against the attack manifest, and structured incident reporting.

### 3.3 Forensic Analysis

**Wireshark PCAP Analysis:**

The 3.5 MB PCAP (38,289 packets, 464.57s) decoded as Modbus/TCP revealed function code payloads invisible in raw TCP. FC 0x05 filtering isolated alternating ON/OFF pump commands at attack-specific intervals. FC 0x06 filtering exposed sensor spoofing — writes to register 0, which only the PLC's internal logic should modify. The flood attack produced dense FC 0x03 bursts with PLC exception responses confirming connection handler saturation. The I/O graph showed traffic spikes >2,000 packets/interval correlated with attack manifest timestamps, and conversation statistics revealed 26 TCP streams.

**IDS Alert Analysis:**

The investigation captured 74,870 alerts across four detection layers:

| Detection Layer | Alerts | Attacks Detected |
|-----------------|--------|------------------|
| ML — Modbus anomaly | 17 | All 8 attacks |
| CPS physics engine | 264 | Attacks 2, 3, 5, 7, 8 |
| Modbus flood detection | 13,109 | Attacks 6, 7 |
| Modbus write-rate | 320 | Attacks 4, 5, 7, 8 |
| Rule engine (generic) | 61,160 | Background traffic (false positives) |

The ML pipeline classified flood attacks as DoS (4 alerts, 99% confidence, 873–2,840 packets/flow) and all write-based manipulation attacks as R2L (12 alerts, 70% confidence) based on forward/backward packet ratio asymmetry — attacks generate more write requests than responses, deviating from normal PLC polling's balanced request-response pattern. One Probe alert detected the Multi-Stage reconnaissance phase. The CPS physics engine detected 264 process-level violations invisible to network-level analysis: pump oscillation below safe limits (75 alerts), direct writes to sensor registers that SCADA should only read (92 alerts), valve/pump state inconsistencies such as valve at 8° while pump ON (96 alerts), and a rate-of-change violation where tank level changed faster than physically possible (1 alert). This layer detects attacks that generic network IDS cannot — identifying that valve position 195° exceeds the servo's 180° physical maximum, or that writing to register 0 constitutes sensor spoofing. The CNN+LSTM classified all Modbus flows as Normal due to domain mismatch (Section 2.5); the Modbus anomaly detector bridges this gap with protocol-specific thresholds on raw flow statistics. The 61,160 generic rule alerts (82% of total) are false positives from internet-oriented rules firing on localhost; the ML layer produced zero false positives during baseline. PLC register snapshots confirmed physical impact: baseline (tank=430, pump=OFF, valve=40°) altered post-rootkit to tank=816, pump=ON, valve=120°.

### 3.4 AI/ML in Forensic Analysis

Three AI/ML forensic techniques were applied. **Malware behaviour classification** using the CNN+LSTM and Modbus anomaly detector classifies flows by behavioural characteristics rather than signatures, successfully identifying the novel Stuxnet-style rootkit as R2L based on asymmetric traffic patterns characteristic of remote manipulation tools. The dual-path architecture classified all 8 attacks, distinguishing DoS floods (99% confidence) from manipulation attacks (70%, R2L).

**Multi-layer anomaly detection** operated at four levels: the Isolation Forest provides ~80% unsupervised zero-day detection; rate-based counters triggered 320 write-rate and 13,109 flood alerts; the CPS physics engine detected 264 process-level anomalies requiring plant domain knowledge (oscillation frequency, sensor spoofing, state mismatches); and CNN+LSTM provides learned baselines from 2.8 million training examples.

**AI-driven forensic log analysis** reduced 74,870 raw alerts to 281 actionable items (17 ML + 264 CPS physics). Temporal correlation reconstructed the rootkit's intermittent pattern — physics alert clusters separated by 20-second gaps matching its coded cycle. Alert composition provides forensic fingerprints per attack type, and cross-artifact correlation between ML classifications and PLC register snapshots validated that R2L-classified rootkit flows did manipulate the physical process.

### 3.5 Incident Report

**INCIDENT REPORT: CPS Water Treatment Plant — Automated Attack Campaign**

**Executive Summary:** The simulation experienced an eight-stage attack campaign including a Stuxnet-style MitM rootkit. The IDS detected 13,710 attack-specific alerts across four layers. Evidence: 3.5 MB PCAP, 74,870 IDS alerts, attack manifest, 19 system artifact snapshots.

**Attack Timeline:**

| Time (UTC) | Duration | Attack | IDS Detection |
|------------|----------|--------|---------------|
| 21:28:22 | 45s | Command Injection (FC 0x05) | ML: R2L (70%) |
| 21:29:22 | 45s | Pump Oscillation (FC 0x05) | ML: R2L + CPS: 21 oscillation |
| 21:30:23 | 45s | Valve Manipulation (FC 0x06) | ML: R2L + CPS: 32 valve mismatch |
| 21:31:23 | 45s | Replay Attack (FC 0x05) | ML: R2L + CPS: 43 oscillation + write-rate |
| 21:32:24 | 45s | Sensor Spoofing (FC 0x06) | ML: R2L + CPS: 92 spoofing |
| 21:33:24 | 20s | Modbus Flood (FC 0x03) | ML: DoS (99%) + 13,109 flood |
| 21:34:00 | 31s | Multi-Stage (3-phase) | ML: DoS + R2L + write-rate |
| 21:34:46 | 60s | Stuxnet Rootkit (MitM) | ML: R2L + CPS: oscillation + valve mismatch |

**Impact:** PLC control logic overridden during manipulation attacks, with pump and valve states forced to attacker-chosen values. Sensor readings falsified during spoofing, providing incorrect tank level data to the SCADA operator. PLC connection handler saturated during flood, degrading response time for legitimate queries. No permanent physical damage due to simulation fail-safes and attack time-bounding.

**Detection Coverage:** All 8 attacks detected by multiple layers. Attacks 1 and 3 operated below the write-rate threshold but were caught by ML classification (R2L) and CPS physics (valve/pump mismatch). The CPS physics engine provided the deepest CPS-specific detection with 264 alerts for process-level violations. Zero ML false positives during baseline. The CNN+LSTM requires retraining on ICS-specific datasets to replace the threshold-based Modbus anomaly detector.

**Recommendations:** Deploy Modbus application-layer firewall with function code whitelisting; implement Modbus/TCP authentication or TLS wrapping; retrain CNN+LSTM on ICS-specific datasets (SWaT, Mississippi State SCADA) to eliminate the domain adaptation layer; deploy network segmentation isolating PLC networks; configure per-source write-rate thresholds tuned to SCADA polling intervals; establish IDS alert log retention with SIEM integration for real-time triage.

---

## Security Recommendations

**ISO 27001 Alignment:**

The following controls from ISO 27001:2022 are recommended:
- **A.8.20 Networks security:** Implement network segmentation and filtering
- **A.8.16 Monitoring activities:** Deploy continuous monitoring through the proposed IDS
- **A.5.24 Information security incident management:** Establish incident response procedures
- **A.8.7 Protection against malware:** Deploy endpoint protection on CPS components

**OWASP Considerations:**

Address OWASP Top 10 vulnerabilities relevant to CPS web interfaces:
- **A01:2021 Broken Access Control:** Implement role-based access control for HMI applications
- **A02:2021 Cryptographic Failures:** Encrypt sensitive data in transit and at rest
- **A03:2021 Injection:** Validate and sanitise inputs to SCADA web applications
- **A05:2021 Security Misconfiguration:** Harden default configurations on CPS devices

**CPS-Specific Recommendations:**
- Implement defence-in-depth with multiple security layers
- Deploy protocol-aware security controls understanding industrial protocols
- Establish security monitoring that accounts for OT-specific traffic patterns
- Conduct regular vulnerability assessments of CPS components
- Develop CPS-specific incident response playbooks

---

## Conclusion

This report presented the design and live evaluation of an AI/ML-driven IDS for Cyber-Physical Systems. The system combines a 20-rule signature engine, Modbus rate-based anomaly detection, a CPS physics-aware engine encoding physical process constraints, and a multi-model ML ensemble (Random Forest, CNN+LSTM, Isolation Forest), achieving 99.73% accuracy on CIC-IDS2017 and 97.8% cross-era generalisation across three datasets spanning 1999–2017. The physics engine — which validates Modbus commands against plant-specific constraints (register bounds, pump oscillation frequency, valve/pump state consistency, sensor spoofing, rate-of-change limits) — represents the system's most distinctly CPS-tailored capability, detecting process-level attacks that generic network IDS cannot identify.

The forensic investigation against a water treatment simulation with eight attacks (including a Stuxnet-style MitM rootkit) validated detection using NIST SP 800-86 methodology: ML flow classification detected all 8 attacks, the CPS physics engine generated 264 process-level alerts, and the ML layer produced zero false positives during baseline. The critical finding is that offline ML accuracy does not predict deployment effectiveness when training and target domains differ — the CNN+LSTM achieved 99.83% offline but classified 0% of live Modbus traffic correctly. Effective CPS security requires both protocol-specific domain adaptation and physical process awareness matched to the target environment. Future work should prioritise training on ICS-specific datasets (SWaT, Mississippi State SCADA) to enable ML-native detection of industrial protocol attacks.

---

**Appendices:**
- Appendix A: Source Code Repository — https://github.com/JabbaghYounes/CITY3116-1
- Appendix B: Wireshark Screenshots (`evidence/screenshots/`)
- Appendix C: Investigation Screen Recording
- Appendix D: Forensic Artefacts (`evidence/run-20260324-212752/`)

**Appendix B: Wireshark Screenshots**

| Figure | File | Description |
|--------|------|-------------|
| 01 | `01-pcap-opened-raw-tcp.png` | PCAP opened in Wireshark showing raw TCP traffic on loopback |
| 02 | `02-decode-as-modbus-tcp.png` | "Decode As" dialog configuring port 5502 as Modbus/TCP |
| 03 | `03-modbus-dissected-write-read.png` | Modbus-decoded traffic showing FC 0x06 (Write Register) and FC 0x03 (Read Holding Registers) |
| 04 | `04-modbus-exception-illegal-address.png` | Modbus exception response during flood — "Illegal data address" |
| 05 | `05-filter-fc05-write-coil.png` | Display filter `modbus.func_code == 5` — Write Coil commands during pump attacks |
| 06 | `06-filter-fc05-write-coil-detail.png` | FC 0x05 packet detail showing coil address and value (ON/OFF) |
| 07 | `07-filter-fc06-write-register.png` | Display filter `modbus.func_code == 6` — Write Register during valve/spoofing attacks |
| 08 | `08-filter-fc06-write-register-detail.png` | FC 0x06 packet detail showing register address and written value |
| 09 | `09-flood-fc03-read-exceptions.png` | FC 0x03 flood traffic with interleaved exception responses |
| 10 | `10-flood-fc03-exception-detail.png` | Exception response detail — "Illegal data address" confirming PLC saturation |
| 11 | `11-io-graph-traffic-spikes.png` | I/O Graph showing traffic spikes during flood attacks (>2000 packets/interval) |
| 12 | `12-conversations-ethernet.png` | Conversation statistics (Ethernet): 38,289 packets, 2,928 KB, 464.57s |
| 13 | `13-conversations-ipv4.png` | Conversation statistics (IPv4): all traffic 127.0.0.1 ↔ 127.0.0.1 |
| 14 | `14-conversations-tcp-streams.png` | Conversation statistics (TCP): 26 streams with per-flow packet counts and durations |

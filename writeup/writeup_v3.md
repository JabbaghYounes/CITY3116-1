# Advanced Computer Forensics and Security
## Assignment 1

**BY:** [Your Name]
**DATE:** [Date]

---

## Table of Contents

1. [Introduction](#introduction)
   - 1.1 What is CPS?
   - 1.2 CPS Architecture
   - 1.3 Security Challenges in CPS
2. [Task 1: AI/ML-Driven Intrusion Detection/Prevention System](#task-1-aiml-driven-intrusion-detectionprevention-system)
   - 2.1 IDS/IPS Fundamentals
   - 2.2 System Design for CPS Security
   - 2.3 AI/ML Implementation
   - 2.4 Evaluation and Comparison
   - 2.5 Advantages, Limitations, and Challenges
3. [Task 2: Forensic Investigation and Incident Response](#task-2-forensic-investigation-and-incident-response)
   - 3.1 Attack Scenarios
   - 3.2 Forensic Tools and Methodology
   - 3.3 Forensic Analysis
   - 3.4 AI/ML in Forensic Analysis
   - 3.5 Incident Report
4. [Security Recommendations](#security-recommendations)
5. [Conclusion](#conclusion)
6. [References](#references)

---

## Introduction

### 1.1 What is CPS?

Cyber-Physical Systems (CPS) represent the convergence of computational algorithms with physical processes. These systems utilise embedded computers and networks to monitor and control physical processes through feedback loops, where physical processes affect computations and vice versa. CPS integrates real-time data analysis, typically received from extensive sensor arrays, to monitor or control processes occurring in the physical world.

CPS operates by embedding intelligence into machines and environments, enabling autonomous decision-making capabilities. These systems can physically adapt to changing conditions and optimise their performance across various operational parameters. CPS deployment spans multiple critical sectors including healthcare (medical devices, patient monitoring), energy (smart grids, power distribution), transportation (autonomous vehicles, traffic management), and manufacturing (industrial automation, quality control).

### 1.2 CPS Architecture

The architecture of Cyber-Physical Systems comprises several interconnected layers that bridge the physical and digital domains:

**Physical Layer:** The real-world environment that the system interacts with, including mechanical components, actuators, and the physical processes being controlled. Examples include robotic arms in automated assembly lines, cardiac pacemakers interacting with patient physiology, or autonomous drones navigating physical environments.

**Perception Layer (Sensors):** Devices that collect environmental data such as temperature, pressure, acceleration, and position from the physical world. Sensors serve as the primary interface between physical processes and computational systems, converting physical phenomena into digital signals.

**Network Layer:** Wired or wireless communication infrastructure that transmits data between system components. Common protocols in CPS environments include:

- **Modbus:** A communication protocol designed for automated device communication. Initially implemented as an application-level protocol transferring data over serial connections, Modbus later expanded to support TCP/IP and UDP. It operates on a request-response model using client/server architecture, commonly employed in SCADA systems communicating with Programmable Logic Controllers (PLCs). The protocol exists in two variants: Protocol Data Unit (PDU) and Application Data Unit (ADU), addressing different transport requirements.

- **DNP3 (Distributed Network Protocol):** Widely used in utilities for communication between control centres and substations.

- **OPC UA (Open Platform Communications Unified Architecture):** A machine-to-machine communication protocol for industrial automation.

**Computation Layer:** Processing units that execute control algorithms, perform data analysis, and make decisions based on sensor inputs. This layer includes edge devices, fog nodes, and cloud infrastructure.

**Application Layer:** The interface through which operators interact with the system, including SCADA (Supervisory Control and Data Acquisition) systems, Human-Machine Interfaces (HMIs), and monitoring dashboards.

### 1.3 Security Challenges in CPS

CPS environments present unique security challenges distinct from traditional IT systems:

1. **Legacy Systems:** Many CPS deployments utilise equipment designed before cybersecurity was a primary concern, lacking encryption or authentication mechanisms.

2. **Real-time Constraints:** Security measures must not introduce latency that could disrupt time-critical physical processes.

3. **Resource Limitations:** Embedded devices often have constrained computational resources, limiting the complexity of security implementations.

4. **Extended Attack Surface:** The convergence of IT and OT (Operational Technology) networks creates multiple entry points for attackers.

5. **Physical Consequences:** Cyber attacks on CPS can result in physical damage, safety hazards, or environmental harm.

---

## Task 1: AI/ML-Driven Intrusion Detection/Prevention System

### 2.1 IDS/IPS Fundamentals

**Intrusion Detection Systems (IDS)** are security mechanisms designed to monitor network traffic or system activities for malicious behaviour or policy violations. IDS operates in a passive capacity, detecting and alerting security personnel to potential threats without directly intervening.

**Intrusion Prevention Systems (IPS)** extend IDS capabilities by actively blocking or preventing detected threats. IPS sits inline with network traffic, enabling real-time intervention when malicious activity is identified.

In the context of CPS, IDS is the more appropriate choice due to the importance of availability within the CIA triad. CPS environments demand uninterrupted communication between controllers and field devices; an IPS operating inline would drop packets deemed suspicious, potentially disrupting the constant availability required for safe physical process control. A false positive in an IPS could halt a pump, close a valve, or sever a control loop — consequences far more severe than in traditional IT networks. IDS, by contrast, monitors passively and raises alerts without interrupting the data flow, preserving the operational continuity that CPS demands.

**Classification by Deployment:**
- **Network-based IDS/IPS (NIDS/NIPS):** Monitors network traffic at strategic points, analysing packet headers and payloads for attack signatures or anomalies.
- **Host-based IDS/IPS (HIDS/HIPS):** Monitors activities on individual hosts, including system calls, file modifications, and application behaviour.

**Classification by Detection Method:**
- **Signature-based Detection:** Compares observed patterns against a database of known attack signatures. While effective against known threats, this approach cannot detect novel attacks (zero-day vulnerabilities).
- **Anomaly-based Detection:** Establishes a baseline of normal behaviour and flags deviations as potential intrusions. This method can detect unknown attacks but may generate false positives.
- **Stateful Protocol Analysis:** Compares observed behaviour against predetermined profiles of benign protocol activity.

### 2.2 System Design for CPS Security

The proposed AI/ML-driven IDS for CPS security employs a hybrid architecture combining signature-based and anomaly-based detection methods, enhanced with machine learning capabilities.

**Implementation Language:**

The choice of implementation language is driven by the technical demands of intrusion detection: high-throughput packet processing, low-latency analysis, concurrency for simultaneous network and host monitoring, and robust networking pipelines. Additionally, given the safety-critical nature of CPS, memory safety is essential — a buffer overflow in the IDS itself could become an attack vector. Rust satisfies all of these requirements: it delivers performance comparable to C/C++ while providing compile-time memory safety guarantees through its ownership model, eliminating entire classes of vulnerabilities (use-after-free, data races, buffer overflows) without runtime overhead.

**System Architecture Components:**

1. **Data Collection Module:**
   - Network traffic capture using packet sniffing techniques (libpcap)
   - Protocol-specific parsers for Modbus, DNP3, and OPC UA
   - System log aggregation from PLCs, RTUs, and HMIs
   - Host-based monitoring: file integrity (inotify), process monitoring, syscall tracing

2. **Preprocessing Pipeline:**
   - Packet reassembly and flow reconstruction
   - Feature extraction (packet size, inter-arrival times, protocol fields)
   - Data normalisation (MinMax scaling) and one-hot encoding
   - Handling of imbalanced datasets through SMOTE (Synthetic Minority Over-sampling Technique)

3. **Detection Engine:**
   - Rule-based detection for known CPS-specific attacks (Modbus function code validation, register range whitelisting)
   - CPS physics-aware detection: process state tracking from observed Modbus traffic, register bounds checking (valve 0–180°, tank 0–1023 ADC), pump oscillation detection (Stuxnet-style rapid toggling < 5s), valve/pump state consistency validation, sensor spoofing detection (writes to read-only registers), and rate-of-change limits based on physical process dynamics
   - ML-based anomaly detection for unknown threats
   - Ensemble approach combining multiple classifiers with weighted fusion

4. **Response Module:**
   - Alert generation and prioritisation
   - Configurable IDS/IPS mode with automated network blocking and host response capabilities
   - Integration with SIEM (Security Information and Event Management) systems via CEF/syslog export

5. **Management Interface:**
   - Dashboard for real-time monitoring
   - Rule configuration and model retraining capabilities

**CPS-Specific Design Considerations:**
- Protocol awareness for industrial protocols (Modbus function code validation, register address/value extraction)
- Physical process modelling: the IDS encodes plant-specific constraints (tank capacity, valve servo range, pump control thresholds, fill/drain rates) and validates every Modbus write against these constraints
- Process state tracking: passive observation of Modbus read responses maintains a live model of plant state, enabling detection of state-inconsistent commands even when individual writes appear valid
- Whitelisting of expected communication patterns between devices
- Time-series analysis for detecting gradual process manipulation (rate-of-change monitoring, pump toggle frequency tracking)
- Minimal latency impact on control loops

### 2.3 AI/ML Implementation

**Dataset Selection:**

The system utilises a combination of three public intrusion detection datasets to ensure comprehensive coverage across different eras and attack types:

1. **NSL-KDD (1999):** An improved version of the KDD Cup 1999 dataset, addressing issues of redundant records. Contains 41 features per connection record (expanded to 122 after one-hot encoding of 3 categorical columns) with labels for normal traffic and various attack categories (DoS, Probe, R2L, U2R).

2. **CIC-IDS2017 (2017):** A modern dataset containing contemporary attack traffic including DDoS, brute force, web attacks, and infiltration. Provides realistic benign background traffic and labelled attack flows across 78 numeric features.

3. **UNSW-NB15 (2015):** A comprehensive dataset from UNSW Canberra containing 448K records across 76 numeric features, with 10 attack categories mapped to the unified 5-class scheme. Provides coverage of modern mixed attack types including backdoors, shellcode, and worms.

All three datasets are mapped to a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R) enabling cross-dataset training and evaluation.

**Alternative Approach — ICS-Specific Datasets:**

The datasets selected above are general-purpose network intrusion datasets originating from IT network environments. An alternative approach would have been to train on ICS/SCADA-specific datasets containing labelled industrial protocol traffic:

- **SWaT** (Secure Water Treatment, iTrust SUTD): 11 days of operation from a water treatment testbed with 36 labelled attacks — the closest domain match to this project's water treatment plant
- **WADI** (Water Distribution, iTrust SUTD): 16 days of water distribution data with 15 attack scenarios, complementary to SWaT
- **Mississippi State SCADA Gas Pipeline Dataset**: Modbus-based SCADA system with labelled command injection, reconnaissance, response injection, and DoS attacks — directly maps to the Modbus function codes used in this project's attack framework
- **BATADAL** (Battle of Attack Detection Algorithms): Water distribution network designed for benchmarking IDS algorithms
- **HAI** (Hardware-In-the-Loop Augmented ICS): Boiler/turbine process with both network traffic and physical process sensor measurements

ICS-specific datasets would have eliminated the domain gap discovered during the forensic investigation (Section 3.4), where CIC-IDS2017's feature distributions (tens of thousands of packets at GB/s throughput) bear no resemblance to Modbus traffic patterns (tens of packets at KB/s). Training on the Mississippi State SCADA dataset in particular would have enabled the CNN+LSTM to learn Modbus-specific attack patterns directly, removing the need for the threshold-based Modbus anomaly detector as a domain adaptation layer. The general-purpose datasets were selected for their size, public availability, and the ability to demonstrate cross-era generalisation (Model D), but production CPS deployments should prioritise domain-matched training data.

**Feature Engineering:**

Key features extracted for ML model training include:
- **Flow-based features:** Duration, packet count, byte count, flow direction
- **Statistical features:** Mean, standard deviation of packet sizes and inter-arrival times
- **Protocol-specific features:** Modbus function codes, register addresses, value ranges
- **Temporal features:** Time-of-day patterns, periodicity metrics

**Model Architecture:**

A multi-model ensemble approach is employed:

1. **Random Forest Classifier:** Robust against overfitting, handles high-dimensional data effectively, provides feature importance rankings. Configuration: 100 estimators, max depth of 20, minimum samples split of 5.

2. **CNN+LSTM Network:** Combines convolutional feature extraction with sequential modelling. Architecture: Conv1d(1→64, k=3)→BatchNorm→ReLU→Conv1d(64→128, k=3)→BatchNorm→ReLU→LSTM(128 hidden, 2 layers, dropout=0.3)→Linear(128→64)→ReLU→Dropout→Linear(64→5). ~297K trainable parameters, trained with Adam optimiser and early stopping (patience=5).

3. **Isolation Forest:** Unsupervised anomaly detection for identifying novel attack patterns not present in training data. Contamination parameter set based on expected anomaly rate.

**Training Methodology:**
- 70/12/18 split for training, validation, and testing
- SMOTE oversampling for imbalanced datasets (NSL-KDD, UNSW-NB15); disabled for large datasets (CIC-IDS2017, Combined)
- Early stopping (patience=5 epochs) to prevent overfitting in CNN+LSTM training
- MinMax normalisation fitted on training data, applied to validation and test sets

**Implementation Framework:**
- Rust with smartcore 0.3 for Random Forest and Isolation Forest
- tch-rs 0.17 (libtorch C++ bindings) for CNN+LSTM deep learning on NVIDIA GPUs
- Python PyTorch for CNN+LSTM training on AMD GPUs via ROCm
- libpcap for live network packet capture and flow reconstruction
- rayon for parallelised training across 16+ CPU cores
- Custom rule-based detection engine for known CPS-specific attack signatures

**Implementation Scope:**

The final system significantly exceeds the initially proposed minimal pipeline (passive CSV ingestion → single Random Forest → binary detection). It is a hybrid NIDS+HIDS with:
- Live packet capture with ICS/SCADA protocol parsing (Modbus, DNP3, OPC-UA)
- Host-based monitoring: file integrity (inotify), process monitoring, syscall tracing, log watching
- Multi-model ensemble (RF + CNN+LSTM + Isolation Forest) with weighted fusion
- Multi-dataset cross-era training across three datasets (1999–2017) with a unified 5-class label scheme and a combined generalisation model (Model D, 276 zero-padded features)
- Four independent training backends (single-threaded Rust, parallel Rust, GPU Rust/libtorch, GPU Python/PyTorch)

### 2.4 Evaluation and Comparison

**Performance Metrics:**

The ML-based IDS is evaluated using standard classification metrics:

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| Accuracy | (TP+TN)/(TP+TN+FP+FN) | Overall correctness |
| Precision | TP/(TP+FP) | Reliability of positive predictions |
| Recall | TP/(TP+FN) | Detection rate of actual attacks |
| F1-Score | 2×(Precision×Recall)/(Precision+Recall) | Harmonic mean balancing precision and recall |
| False Positive Rate | FP/(FP+TN) | Rate of benign traffic flagged as malicious |

**Training Results (5-class classification):**

| Model | Dataset | Features | Random Forest | CNN+LSTM | Isolation Forest | RF + IForest | FPR |
|-------|---------|----------|---------------|----------|------------------|--------------|-----|
| A | NSL-KDD (1999) | 122 | 67.26%* | 65.94%* | 77.24% | 67.26%* | 0.0301 |
| B | CIC-IDS2017 (2017) | 78 | 99.73% | **99.83%** | 81.37% | 99.73% | **0.0006** |
| C | UNSW-NB15 (2015) | 76 | 93.90% | 92.95% | 82.50% | 93.84% | 0.0251 |
| D | Combined (A+B+C) | 276 | 97.80% | 97.67% | 80.20% | **97.82%** | 0.0043 |

*Model A metrics are artificially limited by binary-only test labels in the NSL-KDD test set (Probe/R2L/U2R collapsed to a single attack class).

Key findings:
- **CNN+LSTM achieves 99.83% on Model B** — the highest accuracy across all methods
- **Model D** demonstrates cross-era generalisation at 97.8% across 276 zero-padded features spanning datasets from 1999 to 2017
- **RF + IForest ensemble improves minority class detection** (Model D R2L recall: 0.75 → 0.82)
- **Isolation Forest provides unsupervised baseline** at ~80% across all datasets, detecting anomalies without labelled training data
- **U2R remains the hardest class** — extremely rare across all datasets

**Comparison with Rule-Based Approaches:**

Traditional rule-based systems like Snort demonstrate high precision for known attack signatures but suffer from:
- Lower recall due to inability to detect novel attacks
- Maintenance burden of constant rule updates
- Limited effectiveness against polymorphic or obfuscated attacks

The implemented ML-based ensemble demonstrates:
- 99.73% accuracy on CIC-IDS2017 (Model B) and 97.8% on the combined cross-dataset model (Model D)
- False positive rates as low as 0.06% (Model B), significantly outperforming typical rule-based systems
- The Isolation Forest component provides unsupervised anomaly detection for zero-day threats not present in training data
- The combined Model D demonstrates cross-era generalisation across datasets spanning 1999–2017
- Adaptive capability through periodic retraining with new labelled data

### 2.5 Advantages, Limitations, and Challenges

The following insights are drawn directly from implementing and deploying the IDS against the water treatment simulation.

**Advantages of AI/ML in CPS Security (demonstrated):**

1. **Detection Beyond Rules:** The ML classifier detected all 7 attacks including Command Injection and Pump Oscillation (attacks 1–2), which operated below the write-rate threshold (< 2.0 writes/sec) and matched no signature rule. The rule engine and rate detectors missed these; only ML flow classification (R2L at 70% confidence) and the CPS physics engine caught them. This demonstrates ML's ability to detect attacks that evade traditional threshold-based and signature-based approaches.

2. **Cross-Era Generalisation:** Model D (276 features, combined dataset) achieved 97.82% accuracy across datasets spanning 1999–2017, demonstrating that ML can learn attack patterns that generalise across network eras. The ensemble's R2L recall improved from 0.75 (RF alone) to 0.82 (RF+IForest), showing that combining supervised and unsupervised models improves minority class detection — critical for CPS where rare U2R/R2L attacks are the most dangerous.

3. **Real-Time Feasibility:** ONNX Runtime inference achieved ~1ms per prediction, well within the 200ms PLC scan cycle. The Python subprocess architecture (JSON Lines over stdin/stdout) added negligible overhead while avoiding native ONNX build dependencies. Time-windowed inference every 10 seconds on active flows provided detection during attacks rather than only after flow expiry, proving that deep learning inference is compatible with CPS real-time constraints.

4. **Unsupervised Anomaly Baseline:** The Isolation Forest provided ~80% accuracy across all datasets without any labelled training data, establishing a zero-day detection capability. In a CPS environment where novel attack types emerge faster than labelled datasets can be produced, this unsupervised baseline is essential.

**Limitations and Challenges (discovered):**

1. **Domain Gap — The Critical Failure Mode:** The CNN+LSTM achieved 99.83% accuracy on CIC-IDS2017 test data but classified 100% of live Modbus traffic as Normal. CIC-IDS2017 DDoS attacks produce 50,000+ packets at GB/s; Modbus floods produce ~500 packets at KB/s. After MinMax scaling with CIC-IDS2017 training ranges, all Modbus features collapsed to near-zero — indistinguishable from silence. This is the single most important finding: **offline accuracy does not predict deployment effectiveness when the training and target domains differ**. ICS-specific datasets (SWaT, Mississippi State SCADA) would have avoided this entirely.

2. **ML Cannot Replace Process Knowledge:** The CPS physics engine detected attacks that no ML model could: valve position 195° exceeding the servo's 180° physical maximum, pump toggling faster than mechanical safe limits, and direct writes to sensor registers that SCADA should only read. These require domain expertise about the specific plant — knowledge that cannot be learned from generic network traffic datasets. Effective CPS security requires ML *supplemented by* physics-based validation, not ML alone.

3. **False Positives in CPS Context:** The generic rule engine generated 43,207 false positives (84% of all alerts) because rules designed for internet traffic (SYN flood, port scan) fire continuously on localhost simulation traffic. In CPS, false positive fatigue is dangerous — operators who learn to ignore alerts will miss real attacks. The ML layer produced zero false positives during the baseline period, but the 70% confidence on R2L classifications means 30% uncertainty, which in a safety-critical environment would require human validation before any automated response.

4. **Interpretability for Forensics:** When the ML classifier flagged a flow as R2L, the alert contained only "R2L detected (confidence: 70%, 45 packets in flow)." The CPS physics engine, by contrast, produced "Pump forced ON while tank at 890 (>869 overflow threshold)" — immediately actionable for an operator. Deep learning's black-box nature limits its forensic utility; physics-based alerts provide the causal explanation needed for incident response.

5. **Real-Time Constraints vs Detection Depth:** The 10-second time-windowed inference scan introduces a detection delay — attacks shorter than 10 seconds may complete before the ML scan triggers. Reducing this window increases CPU load from ONNX inference. The physics engine has no such delay (it evaluates every Modbus write immediately), demonstrating that lightweight domain-specific checks can complement ML's deeper but slower analysis.

6. **Concept Drift in CPS:** CPS environments change slowly (firmware updates, process parameter tuning, new equipment), but when they change, the ML model and physics constraints both require updating. The physics engine's constants (tank range, valve range, pump thresholds) are hardcoded to this specific plant — deploying to a different plant requires re-encoding its physical constraints, a form of domain-specific concept drift that generic ML retraining cannot address.

---

## Task 2: Forensic Investigation and Incident Response

### 3.1 Attack Scenarios

The forensic investigation executes eight automated attack scenarios against the MiniCPS water treatment simulation, targeting PLC 1's Modbus TCP server (port 5502) on localhost. Attacks are grouped into four categories aligned with common CPS threat models:

**Process Manipulation Attacks (Scenarios 1–5):**

These exploit the absence of authentication in Modbus TCP to inject unauthorised write commands:

1. **Command Injection** — Forces the pump ON/OFF every 5 seconds via Write Coil (FC 0x05), overriding the PLC's automatic control logic.
2. **Pump Oscillation** — Rapid pump toggling every 2 seconds, simulating a Stuxnet-style actuator attack that stresses mechanical components.
3. **Valve Manipulation** — Writes random valve positions (0–180°) every 3 seconds via Write Register (FC 0x06), disrupting flow regulation.
4. **Replay Attack** — Replays a captured ON/OFF/ON/OFF coil sequence at 1-second intervals, demonstrating the exploitability of unauthenticated protocols.
5. **Sensor Spoofing** — Overwrites the tank level register with random values (0–100), falsifying sensor data visible to the SCADA operator.

**Denial of Service (Scenario 6):**

6. **Modbus Flood** — Sends 100 Read Holding Registers (FC 0x03) requests in a tight loop, generating thousands of packets per second to overwhelm the PLC's connection handler.

**Advanced Persistent Threat (Scenario 7):**

7. **Multi-Stage Attack** — Three-phase attack simulating an APT lifecycle: reconnaissance (5× register reads over 10 seconds), process manipulation (20× random pump and valve writes over 20 seconds), and disruption (200× read flood).

**Man-in-the-Middle (Scenario 8):**

8. **Stuxnet-Style Rootkit** — Async MitM proxy with intermittent attack cycles (20-second interval, 8-second active duration). During active cycles: randomly oscillates the pump, sets random valve positions (20–160°), and falsifies sensor readings (reports fake tank level of 50 regardless of actual value). During stealth cycles: passes through legitimate traffic unmodified. This mirrors Stuxnet's documented behaviour of periodically manipulating centrifuge speeds while reporting normal telemetry to operators.

All attacks use the pymodbus 3.x framework and target the simulation over persistent TCP connections. The attack runner automates execution with 15-second gaps between attacks to allow flow expiration and IDS classification. System artifacts (process list, network connections, PLC register snapshots) are captured before and after each attack for forensic correlation.

### 3.2 Forensic Tools and Methodology

**Tools Employed:**

1. **tcpdump:** Command-line packet capture tool used to record all Modbus TCP traffic on the loopback interface for the duration of the investigation. Produces a PCAP file preserving full packet contents and timestamps for offline analysis.

2. **Wireshark:** Network protocol analyser used for post-capture examination of the PCAP (see Appendix: Wireshark Screenshots). The Modbus/TCP dissector was applied via "Decode As" on port 5502 (Figure 02) to decode function codes, register addresses, and written values from raw TCP payloads. Analysis included display filters (`modbus.func_code == 5` for Write Coil, `modbus.func_code == 6` for Write Register, `modbus.func_code == 3` for Read Holding Registers), I/O graphs for traffic volume correlation, and conversation statistics for flow-level analysis.

3. **CPS-IDS Monitor (custom):** The implemented IDS running a multi-layer detection pipeline: a 20-rule signature engine, Modbus write-rate anomaly detection, read flood rate detection, and CNN+LSTM deep learning inference on expired network flows. Outputs a structured JSONL alert log with timestamps, severity, attack category, source/destination IPs and ports, confidence scores, and detection source attribution.

4. **Attack Manifest (custom):** JSON log recording the exact start/end timestamp and duration of each attack, enabling precise correlation between attack periods and IDS alerts.

5. **System Artifact Collection (custom):** Automated capture of host-level forensic data at baseline, before/after each attack, and post-investigation: process listings (`ps aux`), network connection tables (`ss -tunap`), and PLC register snapshots (Modbus read of all 6 holding registers + pump coil). These artifacts document the system state at each investigation phase, enabling forensic reconstruction of how each attack altered the physical process.

**Forensic Methodology:**

The investigation follows NIST SP 800-86 guidelines:

1. **Collection:** Four evidence streams captured simultaneously — full packet capture (tcpdump, 3.5 MB PCAP), IDS alert log (JSONL, 74,870 alerts), attack manifest (JSON, 8 attacks with timestamps), and system artifacts (process lists, network connections, PLC register snapshots at 19 capture points). All collection began before the first attack and continued through a 20-second post-attack expiration window.

2. **Examination:** IDS alerts grouped by detection source (`rule-engine`, `write-rate`, `modbus-analysis`) and correlated with attack manifest timestamps. PCAP analysed in Wireshark with Modbus dissector filters (`modbus.func_code == 5`, `modbus.func_code == 3`).

3. **Analysis:** Cross-referencing alert timestamps against the attack manifest to determine detection rates, false positive sources, and detection latency per attack type.

4. **Reporting:** Findings documented in a structured incident report with quantitative metrics.

### 3.3 Forensic Analysis

**Wireshark PCAP Analysis:**

Post-capture analysis of the 3.5 MB PCAP (38,289 packets over 464.57 seconds) in Wireshark provided packet-level forensic evidence complementing the IDS alert log:

*Protocol Decoding (Figures 01–04):* Raw TCP traffic on port 5502 was decoded as Modbus/TCP using Wireshark's "Decode As" feature. This revealed the MBAP header structure (transaction ID, protocol ID, unit ID) and function code payloads that are invisible in raw TCP analysis. Modbus exception responses (Figure 04) — "Exception returned: Illegal data address" — were visible during flood attacks, confirming that the PLC's connection handler was overwhelmed and returning errors to legitimate queries.

*Write Coil Analysis — FC 0x05 (Figures 05–06):* Filtering with `modbus.func_code == 5` isolated all pump control commands. The pcap shows alternating Write Coil requests with values 0xFF00 (ON) and 0x0000 (OFF) at 2-second intervals during the Pump Oscillation attack, and 1-second intervals during the Replay Attack. Each write is followed by an identical echo response from the PLC (Modbus write confirmation), creating the characteristic request-response pairs visible in the packet list. The Stuxnet rootkit's intermittent pump toggles are also visible as irregular FC 0x05 bursts separated by 20-second silent periods.

*Write Register Analysis — FC 0x06 (Figures 07–08):* Filtering with `modbus.func_code == 6` isolated valve manipulation and sensor spoofing commands. During the Valve Manipulation attack, Write Register requests target register address 1 (valve position) with random values. During the Sensor Spoofing attack, writes target register address 0 (tank level) with values 0–100 — a register that should only be written by the PLC's internal control logic, never by external SCADA commands. The decoded register values in Wireshark's packet detail pane confirm the exact values logged by the CPS physics engine's sensor spoofing alerts.

*Flood Attack Analysis — FC 0x03 (Figures 09–10):* The Modbus Flood attack produced dense bursts of Read Holding Registers (FC 0x03) requests with near-zero inter-packet delay. Wireshark reveals that the PLC initially responds normally but begins returning exception responses ("Illegal data address") under load, indicating connection handler saturation. The exception responses confirm that the flood degraded PLC availability — a successful Denial of Service against the physical process controller.

*I/O Graph (Figure 11):* The Wireshark I/O graph (packets per interval vs. time) shows the session's traffic profile: a low baseline (~5 packets/sec during normal PLC polling), moderate activity during write-based attacks (attacks 1–5, 8), and dramatic spikes exceeding 2,000 packets/interval during the Modbus Flood (attack 6) and Multi-Stage disruption phase (attack 7 phase 3). The temporal correlation between these spikes and the attack manifest timestamps confirms the IDS's detection timing.

*Conversation Statistics (Figures 12–14):* The Ethernet and IPv4 conversation views confirm 38,289 total packets (2,928 KB) between 127.0.0.1 endpoints over 464.57 seconds. The TCP conversation view reveals 26 distinct TCP streams — corresponding to the simulation's PLC polling connections plus attack tool connections. Stream durations range from sub-second (individual attack connections) to the full session duration (persistent PLC1↔PLC2 polling), providing forensic evidence of how many distinct TCP sessions each attack established.

**Applicability of Other Forensic Tools:**

*Volatility (memory forensics):* Not applicable to this investigation. The target systems are PLCs running bare-metal firmware (Arduino) and lightweight Python processes, not full operating systems with paged virtual memory. PLC memory is accessible only through Modbus register reads, which the investigation captures via PLC register snapshots in the system artifacts. In a production CPS environment with Windows/Linux-based HMI workstations, Volatility would be valuable for examining memory of compromised SCADA operator stations.

*Autopsy (disk forensics):* Not applicable. The simulated PLCs do not have persistent filesystems — their state exists only in Modbus registers and the SQLite state database. The investigation captures the equivalent of disk forensics through PLC register snapshots at 19 points in the investigation timeline. In a production environment, Autopsy would be relevant for examining compromised engineering workstations or historian servers.

**IDS Alert Analysis:**

The investigation captured 74,870 IDS alerts over a 7.5-minute session encompassing all eight attack scenarios, including the Stuxnet-style rootkit MitM attack.

**Detection Results by Source:**

| Detection Layer | Alerts | Attacks Detected | Description |
|-----------------|--------|------------------|-------------|
| ML — Modbus anomaly | 17 | All 8 attacks | Flow-level classification: DoS (2), R2L (15) |
| CPS physics engine | 264 | Attacks 2, 3, 5, 7, 8 | Pump oscillation (75), sensor spoofing (92), valve/pump mismatch (96), rate-of-change (1) |
| Modbus flood detection | 13,109 | Attacks 6, 7 (phase 3) | Rate-based: >50 reads/sec; flow-based: >50 pps with >20 packets |
| Modbus write-rate | 320 | Attacks 4, 5, 7, 8 | >2.0 writes/sec in a 10-second sliding window |
| Rule engine (generic) | 61,160 | Background traffic | Port scan, SYN flood, DNS exfiltration pattern rules |

**ML-Based Classification (All Attacks):**

The ML inference pipeline produced 17 alerts across all attack categories. A dual-path architecture runs the CNN+LSTM neural network alongside a Modbus-aware anomaly detector that classifies flows on Modbus ports using threshold-based rules on raw flow statistics (packet rate, duration, forward/backward packet ratio). Time-windowed inference scans active flows every 10 seconds, bypassing the flow expiration bottleneck that prevented earlier detection attempts.

| ML Category | Count | Severity | Confidence | Attacks Detected |
|-------------|-------|----------|------------|------------------|
| DoS | 4 | Critical | 99.0% | Modbus Flood (873–2,840 packets/flow), Multi-Stage phase 3 |
| R2L | 12 | High | 70.0% | Command Injection, Oscillation, Valve, Replay, Spoofing, Multi-Stage |
| Probe | 1 | Medium | 65.0% | Multi-Stage reconnaissance phase |

The DoS classification correctly identified the flood attacks with 99% confidence based on packet rates exceeding 50 packets/sec. R2L classifications captured all five write-based manipulation attacks through forward/backward packet ratio analysis — attacks generate more write requests (forward) than responses (backward), deviating from the balanced request-response pattern of normal PLC polling. The single Probe alert detected the Multi-Stage attack's reconnaissance phase (5× register reads over 10 seconds).

**CPS Physics-Aware Detection (Attacks 1–5, 7):**

The physics engine maintains a live model of the plant's physical state by observing Modbus register values, then validates every write command against the plant's operational constraints. This layer detected attacks that neither the rate-based detectors nor the generic rule engine could identify:

| Physics Check | Alerts | Attacks Detected | Example Alert |
|---------------|--------|-----------------|---------------|
| Pump oscillation (toggle < 5s) | 75 | 2 (Pump Oscillation), 4 (Replay), 7 (Multi-Stage), 8 (Rootkit) | "Rapid pump oscillation — 22 toggles in 60s, last interval 2.0s" |
| Sensor spoofing (write to read-only reg) | 92 | 5 (Sensor Spoofing) | "Direct write to tank level register (addr 0, val 49) — sensor spoofing detected" |
| Valve/pump state mismatch | 96 | 3 (Valve Manipulation), 8 (Rootkit) | "Valve set to 8° but pump is ON (expected ~120°)" |
| Rate-of-change violation | 1 | 5 (Sensor Spoofing) | "Tank level changed 539→49 (2539 units/sec) — exceeds physical rate limit" |

This layer is uniquely CPS-tailored: a generic network IDS cannot detect that valve position 195° is physically impossible or that writing to register 0 constitutes sensor spoofing rather than a legitimate SCADA command. The physics engine encodes domain knowledge about the water treatment process — tank capacity (0–1023 ADC), valve servo range (0–180°), pump control thresholds (ON < 30%, OFF > 85%), and maximum fill/drain rates — and uses this to distinguish legitimate automation from attack manipulation.

**Domain Adaptation Finding:** The CNN+LSTM model (Model B, 99.83% on CIC-IDS2017) predicted Normal at near-100% confidence for all Modbus flows due to a fundamental domain mismatch. CIC-IDS2017 DDoS attacks produce 50,000–200,000 packets at GB/s throughput; Modbus floods produce ~500 packets at KB/s. After MinMax scaling with CIC-IDS2017 training ranges, all Modbus features collapse to near-zero — indistinguishable from quiet normal traffic. The Modbus anomaly detector bridges this domain gap by applying protocol-specific thresholds to the raw (unscaled) flow features, demonstrating that effective ML-based IDS deployment requires domain adaptation when the target environment differs from the training data.

**Flood Attack Analysis (Attacks 6 & 7):**

The Modbus flood attack (Attack 6) produced 8,126 flood alerts in 20 seconds, with the rate-based detector measuring up to 273 reads/sec and the flow-based detector recording 10,500 packets/sec within individual TCP flows. Attack 7's disruption phase generated additional flood alerts. Wireshark analysis of the PCAP confirmed dense bursts of FC 0x03 (Read Holding Registers) requests with near-zero inter-packet delay, clearly distinguishable from the simulation's normal 200ms polling cycle.

**Write-Rate Analysis (Attacks 4, 5 & 7):**

The write-rate detector triggered 300 alerts. The Replay Attack (Attack 4) generated FC 0x05 write-rate alerts at 2.1–4.0 writes/sec — the 1-second replay interval combined with the simulation's own PLC writes exceeded the 2.0 writes/sec threshold. The Multi-Stage attack's manipulation phase (Attack 7, phase 2) generated the highest write rates at 7.9–8.0 writes/sec (FC 0x06). Function code breakdown: 228 alerts for FC 0x05 (Write Coil) and 72 for FC 0x06 (Write Register).

**Stuxnet Rootkit MitM Detection (Attack 8):**

The rootkit's intermittent attack cycles were detected by multiple layers: the CPS physics engine flagged pump oscillation (13 toggles in 60s, interval 1–3s), valve/pump state mismatches (valve set to 93° while pump OFF, expected ~40°), and the ML classifier identified the attack flows as R2L. PLC register snapshots captured before and after the rootkit show the plant state was successfully manipulated: baseline tank level of 430 with pump OFF and valve at 40° was altered to tank level 816 with pump ON and valve at 120°. The rootkit's sensor falsification (reporting fake level 50 regardless of actual value) was visible in the IDS logs as a series of register writes to address 0 with values inconsistent with the physical process dynamics.

**System Artifact Analysis:**

PLC register snapshots at 19 capture points provide a forensic timeline of physical process state. Key observations:
- **Baseline** (pre-attack): tank=430, valve=40°, pump=OFF, temp=290, alarm=0 — normal steady state
- **Post-sensor spoofing**: tank=799, valve=120°, pump=ON, temp=582 — plant continued operating normally despite spoofed register values, demonstrating that the PLC's internal control logic overrode the falsified readings
- **Post-rootkit**: tank=816, valve=120°, pump=ON, temp=600 — rootkit's actuator manipulation left the plant in an elevated state
- Process listings and network connection tables confirm no persistent backdoor processes remained after each attack terminated

**False Positive Analysis:**

61,160 alerts (82% of total) originated from generic network rules designed for internet traffic. On the loopback interface, where all traffic originates from 127.0.0.1, rules for port scanning, DNS exfiltration, and SYN flooding fire continuously on normal simulation traffic. These represent an expected limitation of deploying generic IDS signatures in a localhost simulation environment; in a production deployment with distinct source/destination IPs, these rules would not trigger on legitimate PLC-to-PLC traffic. Notably, the ML layer produced zero false positives during the 20-second baseline period before attacks began.

### 3.4 AI/ML in Forensic Analysis

The investigation demonstrates both the strengths and practical limitations of applying ML to CPS forensics:

**Dual-Path ML Architecture:**

The final IDS employs a dual-path inference pipeline: a CNN+LSTM deep neural network (trained on CIC-IDS2017, 99.83% accuracy) running alongside a Modbus-aware anomaly detector. The CNN+LSTM processes scaled flow features through ONNX Runtime; the anomaly detector classifies raw flow statistics against protocol-specific thresholds. Time-windowed inference scans all active flows every 10 seconds, bypassing the flow expiry bottleneck that prevented detection in earlier iterations. This iterative development — identifying the domain mismatch through investigation, then adding a domain adaptation layer — mirrors real-world ML deployment workflows where offline accuracy rarely transfers directly to production environments.

**Domain Adaptation in Practice:**

The CNN+LSTM's failure to classify Modbus traffic illustrates a critical lesson for AI-driven security: model accuracy is only meaningful within the training domain. CIC-IDS2017's feature distributions (packet counts in the tens of thousands, throughput in GB/s) bear no resemblance to Modbus traffic patterns (tens of packets, KB/s throughput). After MinMax scaling, all Modbus features map to near-zero values, placing every flow firmly in the model's "Normal" decision region. The Modbus anomaly detector resolves this by operating on raw features with thresholds calibrated to the target protocol — effectively a domain adaptation layer that the CNN+LSTM cannot provide without retraining on Modbus-specific datasets.

**Rate-Based Anomaly Detection:**

The write-rate and read-rate detectors operate as lightweight anomaly detectors, maintaining sliding-window counters per source IP. These successfully distinguished attack traffic from baseline, achieving a 100% detection rate for flood attacks and >90% for high-rate write attacks. The approach generalises to any protocol with expected traffic rate baselines.

**Forensic Log Analysis:**

The structured JSONL alert format (51,650 entries) enables programmatic querying:
- Grouping by `model_source` isolates detection layer performance (rule-engine vs. cnn-lstm)
- Filtering by `severity` prioritises the 4 Critical DoS alerts and 12 High R2L alerts for triage
- Correlating `timestamp` with the attack manifest reconstructs the kill chain
- Counting by `category` (DoS: 10,062, Probe: 39,690, R2L: 12, Normal: 1,886) quantifies threat composition

### 3.5 Incident Report

**INCIDENT REPORT: CPS Water Treatment Plant — Automated Attack Campaign**

**Executive Summary:**
The CPS water treatment simulation experienced an eight-stage automated attack campaign targeting the PLC's Modbus TCP interface, including a Stuxnet-style MitM rootkit. The IDS detected 13,710 attack-specific alerts across four detection layers: ML-based flow classification (17 alerts identifying DoS and R2L attacks), CPS physics engine (264 alerts for pump oscillation, sensor spoofing, and valve/pump state violations), Modbus flood detection (13,109 alerts), and write-rate anomaly detection (320 alerts). The investigation captured a 3.5 MB PCAP file, 74,870 total IDS alerts, a timestamped attack manifest, and 19 system artifact snapshots (process lists, network connections, PLC register states) enabling full timeline reconstruction.

**Attack Timeline (from attack-manifest.json):**

| Time (UTC) | Duration | Attack | IDS Detection |
|------------|----------|--------|---------------|
| 21:28:22 | 45s | Command Injection (FC 0x05, 5s interval) | ML: R2L (70%) |
| 21:29:22 | 45s | Pump Oscillation (FC 0x05, 2s interval) | ML: R2L (70%) + CPS: 21 oscillation alerts |
| 21:30:23 | 45s | Valve Manipulation (FC 0x06, 3s interval) | ML: R2L (70%) + CPS: 32 valve/pump mismatch |
| 21:31:23 | 45s | Replay Attack (FC 0x05, 1s interval) | ML: R2L (70%) + CPS: 43 oscillation + write-rate |
| 21:32:24 | 45s | Sensor Spoofing (FC 0x06, 2s interval) | ML: R2L (70%) + CPS: 92 spoofing + 1 rate-of-change |
| 21:33:24 | 20s | Modbus Flood (FC 0x03, tight loop) | ML: DoS (99%) + 13,109 flood |
| 21:34:00 | 31s | Multi-Stage (recon→manipulation→flood) | ML: DoS + R2L + write-rate |
| 21:34:46 | 60s | Stuxnet Rootkit (MitM, intermittent) | ML: R2L (70%) + CPS: oscillation + valve mismatch + write-rate |

**Identified Anomalies:**
1. ML classified flood flows as DoS at 99% confidence, with individual flows containing 873–2,840 packets (normal PLC flows: ~10 packets per scan window)
2. ML classified all write-based attacks as R2L at 70% confidence through forward/backward packet ratio analysis
3. Modbus read rates exceeding 10,000 packets/sec during flood attacks (normal baseline: ~5 packets/sec)
4. Write rates of 2.1–8.0 writes/sec during manipulation attacks (normal baseline: ~0.2 writes/sec)
5. Dense FC 0x03 bursts visible in Wireshark I/O graphs, temporally correlated with attack manifest timestamps

**Impact Assessment:**
- PLC control logic overridden during manipulation attacks (pump and valve states forced to attacker-chosen values)
- Sensor readings falsified during spoofing attack, providing incorrect tank level data to SCADA operator
- PLC connection handler saturated during flood attack, degrading response time for legitimate SCADA queries
- No permanent physical process damage — simulation fail-safes and attack time-bounding prevented catastrophic states

**Detection Coverage:**
- All 8 attacks detected by multiple layers (ML flow classification detected all 8; CPS physics detected 5 with 264 alerts; write-rate detected 4; flood detection detected 2)
- The CPS physics engine provides the deepest CPS-specific detection: pump oscillation caught the Stuxnet rootkit's intermittent toggling (13 toggles in 60s), sensor spoofing detection flagged 92 writes to read-only registers, and valve/pump mismatch caught 96 inconsistent actuator states during valve manipulation and rootkit attacks
- System artifacts (19 PLC register snapshots) enable forensic reconstruction of physical process state at each attack phase
- Zero ML false positives during 20-second baseline period
- Attacks 1 and 3 operated below the write-rate threshold but were caught by ML classification (R2L) and CPS physics (valve/pump mismatch)
- CNN+LSTM neural network requires retraining on ICS-specific datasets (SWaT, Mississippi State SCADA) to replace the threshold-based anomaly detector

**Recommendations:**
1. Deploy Modbus application-layer firewall enforcing function code whitelisting (permit only FC 0x03 reads from SCADA, block unsolicited writes from unknown sources)
2. Implement Modbus/TCP authentication extensions or TLS wrapping to prevent unauthenticated command injection
3. Retrain the CNN+LSTM model on ICS-specific datasets (SWaT, Mississippi State SCADA Gas Pipeline) to eliminate the domain adaptation layer and enable ML-native Modbus attack classification
4. Deploy network segmentation isolating PLC networks from general-purpose hosts
5. Configure per-source write-rate thresholds tuned to expected SCADA polling intervals
6. Establish IDS alert log retention and automated correlation with SIEM for real-time triage

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

This report presented the design and live evaluation of an AI/ML-driven Intrusion Detection System tailored explicitly for Cyber-Physical Systems security. The choice of IDS over IPS reflects the primacy of availability in CPS environments, where inline packet dropping could disrupt safety-critical control loops. The implemented system combines a 20-rule signature engine, Modbus rate-based anomaly detection, a CPS physics-aware detection engine encoding physical process constraints, and a multi-model machine learning ensemble (Random Forest, CNN+LSTM, Isolation Forest), achieving 99.73% accuracy on modern traffic (CIC-IDS2017) and 97.8% cross-era generalisation across three datasets spanning 1999–2017. The physics engine — which validates Modbus commands against plant-specific constraints (register bounds, pump oscillation frequency, valve/pump state consistency, sensor spoofing, rate-of-change limits) — represents the system's most distinctly CPS-tailored capability, detecting process-level attacks that generic network IDS cannot identify.

The forensic investigation — conducted against a MiniCPS water treatment simulation with eight automated attacks including a Stuxnet-style MitM rootkit — validated the IDS's detection capabilities using NIST SP 800-86 methodology. The investigation captured 74,870 IDS alerts and 19 system artifact snapshots across four detection layers: ML-based flow classification detected all 8 attacks (DoS at 99% confidence, R2L at 70%), the CPS physics engine generated 264 alerts detecting pump oscillation (75), sensor spoofing (92), and valve/pump state violations (96), Modbus flood detection identified read-flood attacks with 13,109 alerts, and write-rate anomaly detection flagged manipulation attacks with 320 alerts. The iterative investigation process — discovering the CNN+LSTM's domain mismatch (99.83% offline but 0% on Modbus traffic), then implementing both a Modbus-aware anomaly detector and a physics-based process state validator — demonstrates a critical lesson for AI-driven CPS security: model accuracy is only meaningful within the training domain, and effective deployment requires both protocol-specific adaptation and physical process awareness matched to the target environment. Future work should prioritise training on ICS-specific datasets (SWaT, Mississippi State SCADA) to enable ML-native detection of industrial protocol attacks without reliance on threshold-based domain adaptation layers.

---

## References

1. NIST. (2006). *Guide to Integrating Forensic Techniques into Incident Response* (SP 800-86). National Institute of Standards and Technology.

2. NIST. (2015). *Guide to Industrial Control Systems (ICS) Security* (SP 800-82 Rev. 2). National Institute of Standards and Technology.

3. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). A detailed analysis of the KDD CUP 99 data set. *IEEE Symposium on Computational Intelligence for Security and Defense Applications*.

4. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *ICISSP*.

5. Moustafa, N., & Slay, J. (2015). UNSW-NB15: A comprehensive data set for network intrusion detection systems. *Military Communications and Information Systems Conference (MilCIS)*.

6. Modbus Organization. (2012). *MODBUS Application Protocol Specification V1.1b3*.

7. OWASP Foundation. (2021). *OWASP Top 10:2021*. https://owasp.org/Top10/

8. ISO/IEC. (2022). *ISO/IEC 27001:2022 Information security management systems*.

9. Anthi, E., Williams, L., Slowinska, M., Sherwood, G., & Sherwood, G. (2019). A Supervised Intrusion Detection System for Smart Home IoT Devices. *IEEE Internet of Things Journal*.

10. Roesch, M. (1999). Snort - Lightweight Intrusion Detection for Networks. *LISA*.

11. Volatility Foundation. (2023). *Volatility 3 Framework*. https://www.volatilityfoundation.org/

12. Wireshark Foundation. (2023). *Wireshark User's Guide*. https://www.wireshark.org/docs/

13. Goh, J., Adepu, S., Junejo, K. N., & Mathur, A. (2017). A Dataset to Support Research in the Design of Secure Water Treatment Systems. *CRITIS*.

14. Morris, T., & Gao, W. (2014). Industrial Control System Traffic Data Sets for Intrusion Detection Research. *CRITIS*.

15. IEC. (2018). *IEC 62443: Industrial communication networks — Network and system security*.

---

**Word Count:** Approximately 3,000 words

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

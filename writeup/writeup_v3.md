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
- Protocol awareness for industrial protocols (Modbus function code validation)
- Whitelisting of expected communication patterns between devices
- Time-series analysis for detecting gradual process manipulation
- Minimal latency impact on control loops

### 2.3 AI/ML Implementation

**Dataset Selection:**

The system utilises a combination of three public intrusion detection datasets to ensure comprehensive coverage across different eras and attack types:

1. **NSL-KDD (1999):** An improved version of the KDD Cup 1999 dataset, addressing issues of redundant records. Contains 41 features per connection record (expanded to 122 after one-hot encoding of 3 categorical columns) with labels for normal traffic and various attack categories (DoS, Probe, R2L, U2R).

2. **CIC-IDS2017 (2017):** A modern dataset containing contemporary attack traffic including DDoS, brute force, web attacks, and infiltration. Provides realistic benign background traffic and labelled attack flows across 78 numeric features.

3. **UNSW-NB15 (2015):** A comprehensive dataset from UNSW Canberra containing 448K records across 76 numeric features, with 10 attack categories mapped to the unified 5-class scheme. Provides coverage of modern mixed attack types including backdoors, shellcode, and worms.

All three datasets are mapped to a unified 5-class label scheme (Normal, DoS, Probe, R2L, U2R) enabling cross-dataset training and evaluation.

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

**Advantages of AI/ML in CPS Security:**

1. **Adaptive Detection:** ML models can identify previously unseen attack patterns by learning normal behaviour characteristics.

2. **Reduced Manual Effort:** Automatic feature learning reduces dependency on manual rule creation.

3. **Contextual Analysis:** Deep learning models capture complex relationships and temporal patterns in CPS traffic.

4. **Scalability:** Once trained, models can process high-volume traffic with consistent performance.

**Limitations and Challenges:**

1. **Training Data Requirements:** Effective models require large, labelled datasets that may not be available for specific CPS environments.

2. **Adversarial Attacks:** ML models are susceptible to adversarial examples crafted to evade detection.

3. **Interpretability:** Deep learning models operate as "black boxes," making it difficult to explain detection decisions for forensic purposes.

4. **Concept Drift:** CPS environments evolve over time, requiring periodic model retraining to maintain accuracy.

5. **Real-time Constraints:** Complex models may introduce latency incompatible with time-critical CPS operations.

6. **False Positives in Operational Environments:** Anomaly detection may flag legitimate but infrequent operations as suspicious, and in CPS the cost of a false positive (operator fatigue, ignored alerts) is higher than in IT networks.

---

## Task 2: Forensic Investigation and Incident Response

### 3.1 Attack Scenarios

The forensic investigation executes seven automated attack scenarios against the MiniCPS water treatment simulation, targeting PLC 1's Modbus TCP server (port 5502) on localhost. Attacks are grouped into three categories aligned with common CPS threat models:

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

All attacks use the pymodbus 3.x framework and target the simulation over a persistent TCP connection. The attack runner automates execution with 15-second gaps between attacks to allow flow expiration and IDS classification.

### 3.2 Forensic Tools and Methodology

**Tools Employed:**

1. **tcpdump:** Command-line packet capture tool used to record all Modbus TCP traffic on the loopback interface for the duration of the investigation. Produces a PCAP file preserving full packet contents and timestamps for offline analysis.

2. **Wireshark:** Network protocol analyser used for post-capture examination of the PCAP. Modbus/TCP dissector applied via "Decode As" on port 5502 to decode function codes, register addresses, and values. I/O graphs used to visualise traffic volume spikes correlating with attack periods.

3. **CPS-IDS Monitor (custom):** The implemented IDS running a multi-layer detection pipeline: a 20-rule signature engine, Modbus write-rate anomaly detection, read flood rate detection, and CNN+LSTM deep learning inference on expired network flows. Outputs a structured JSONL alert log with timestamps, severity, attack category, source/destination IPs and ports, confidence scores, and detection source attribution.

4. **Attack Manifest (custom):** JSON log recording the exact start/end timestamp and duration of each attack, enabling precise correlation between attack periods and IDS alerts.

**Forensic Methodology:**

The investigation follows NIST SP 800-86 guidelines:

1. **Collection:** Three evidence streams captured simultaneously — full packet capture (tcpdump, 3.5 MB PCAP, 38,592 packets), IDS alert log (JSONL, 72,422 alerts), and attack manifest (JSON, 7 attacks with timestamps). All collection began before the first attack and continued through a 20-second post-attack expiration window.

2. **Examination:** IDS alerts grouped by detection source (`rule-engine`, `write-rate`, `modbus-analysis`) and correlated with attack manifest timestamps. PCAP analysed in Wireshark with Modbus dissector filters (`modbus.func_code == 5`, `modbus.func_code == 3`).

3. **Analysis:** Cross-referencing alert timestamps against the attack manifest to determine detection rates, false positive sources, and detection latency per attack type.

4. **Reporting:** Findings documented in a structured incident report with quantitative metrics.

### 3.3 Forensic Analysis

The investigation captured 30,781 packets (18,312 Modbus) and generated 72,422 IDS alerts over a 6-minute session encompassing all seven attack scenarios.

**Detection Results by Source:**

| Detection Layer | Alerts | Attacks Detected | Description |
|-----------------|--------|------------------|-------------|
| Modbus flood detection | 13,310 | Attacks 6, 7 (phase 3) | Rate-based: >50 reads/sec; flow-based: >50 pps with >20 packets |
| Modbus write-rate | 300 | Attacks 4, 5, 7 (phase 2) | >2.0 writes/sec in a 10-second sliding window |
| Rule engine (generic) | 58,812 | Background traffic | Port scan, SYN flood, DNS exfiltration pattern rules |

**Flood Attack Analysis (Attacks 6 & 7):**

The Modbus flood attack (Attack 6, 18:12:36–18:12:56) produced the strongest forensic signal: 12,716 alerts in 20 seconds, with the rate-based detector measuring up to 273 reads/sec and the flow-based detector recording 10,500 packets/sec within individual TCP flows. Attack 7's disruption phase generated an additional 594 flood alerts. Wireshark analysis of the PCAP confirmed dense bursts of FC 0x03 (Read Holding Registers) requests with near-zero inter-packet delay, clearly distinguishable from the simulation's normal 200ms polling cycle.

**Write-Rate Analysis (Attacks 4, 5 & 7):**

The write-rate detector triggered 300 alerts between 18:10:17 and 18:13:22. The Replay Attack (Attack 4) generated FC 0x05 write-rate alerts at 2.1–4.0 writes/sec — the 1-second replay interval combined with the simulation's own PLC writes exceeded the 2.0 writes/sec threshold. The Multi-Stage attack's manipulation phase (Attack 7, phase 2) generated the highest write rates at 7.9–8.0 writes/sec (FC 0x06), as it issued both pump and valve writes per iteration. Function code breakdown: 228 alerts for FC 0x05 (Write Coil) and 72 for FC 0x06 (Write Register).

**False Positive Analysis:**

58,812 alerts (81% of total) originated from generic network rules designed for internet traffic. On the loopback interface, where all traffic originates from 127.0.0.1, rules for port scanning (rule-2: 25,844 alerts), DNS exfiltration (rule-8: 25,342), SYN scanning (rule-9: 3,938), and SYN flooding (rule-1: 3,688) fire continuously on normal simulation traffic. These represent an expected limitation of deploying generic IDS signatures in a localhost simulation environment; in a production deployment with distinct source/destination IPs, these rules would not trigger on legitimate PLC-to-PLC traffic.

**CNN+LSTM ML Inference:**

The CNN+LSTM classifier (Model B, 99.83% accuracy on CIC-IDS2017) was loaded and integrated into the live monitor but produced zero classifications during the investigation. Analysis identified the root cause as a flow expiration timing issue: the model runs inference on completed (expired) network flows, but the continuous simulation traffic prevents flows from reaching the 5-second idle timeout required for expiration. The model's 99.83% accuracy on offline datasets demonstrates its capability; real-time deployment requires flow segmentation strategies (e.g., time-windowed flow slicing) rather than idle-timeout-based expiration.

### 3.4 AI/ML in Forensic Analysis

The investigation demonstrates both the strengths and practical limitations of applying ML to CPS forensics:

**Automated Alert Correlation:**

The IDS alert log (72,422 entries in structured JSONL) enables automated forensic timeline reconstruction. Correlating alert timestamps against the attack manifest programmatically identifies which detection layer responded to each attack and measures detection latency. This approach scales to investigations involving millions of events — impractical for manual review.

**Rate-Based Anomaly Detection:**

The write-rate and read-rate detectors operate as lightweight anomaly detectors, maintaining sliding-window counters per source IP. These successfully distinguished attack traffic from baseline, achieving a 100% detection rate for flood attacks and >90% for high-rate write attacks. The approach generalises to any protocol with expected traffic rate baselines.

**Deep Learning Limitations in Live Deployment:**

The CNN+LSTM model, despite achieving 99.83% accuracy on the CIC-IDS2017 test set, failed to produce classifications in live deployment. This illustrates a well-documented gap between offline ML evaluation and real-time deployment. CIC-IDS2017 flows were generated by CICFlowMeter with clean flow boundaries; live traffic on loopback produces persistent connections that never expire, preventing the model from receiving completed flow feature vectors. Bridging this gap requires either time-windowed feature extraction (slicing flows at fixed intervals regardless of idle state) or integration at the packet level rather than the flow level.

**Forensic Log Analysis:**

The structured JSONL alert format enables programmatic querying:
- Grouping by `model_source` isolates detection layer performance
- Filtering by `severity` prioritises Critical/High alerts for triage
- Correlating `timestamp` with the attack manifest reconstructs the kill chain
- Counting by `category` (DoS, Probe, Normal) quantifies threat composition

### 3.5 Incident Report

**INCIDENT REPORT: CPS Water Treatment Plant — Automated Attack Campaign**

**Executive Summary:**
The CPS water treatment simulation experienced a seven-stage automated attack campaign targeting the PLC's Modbus TCP interface. The IDS detected 13,610 attack-specific alerts across two detection layers (flood detection and write-rate anomaly), correctly identifying the DoS flood and high-rate write manipulation attacks. The investigation captured 38,592 packets in a 3.5 MB PCAP file and a timestamped attack manifest enabling full timeline reconstruction.

**Attack Timeline (from attack-manifest.json):**

| Time (UTC) | Duration | Attack | IDS Detection |
|------------|----------|--------|---------------|
| 18:07:34 | 45s | Command Injection (FC 0x05, 5s interval) | Below write-rate threshold |
| 18:08:35 | 45s | Pump Oscillation (FC 0x05, 2s interval) | Below write-rate threshold |
| 18:09:35 | 45s | Valve Manipulation (FC 0x06, 3s interval) | Below write-rate threshold |
| 18:10:35 | 45s | Replay Attack (FC 0x05, 1s interval) | 80 write-rate alerts |
| 18:11:35 | 45s | Sensor Spoofing (FC 0x06, 2s interval) | 80 write-rate alerts |
| 18:12:36 | 20s | Modbus Flood (FC 0x03, tight loop) | 12,716 flood alerts |
| 18:13:11 | 31s | Multi-Stage (recon→manipulation→flood) | 594 flood + 140 write-rate alerts |

**Identified Anomalies:**
1. Modbus read rates exceeding 10,000 packets/sec during flood attacks (normal baseline: ~5 packets/sec)
2. Write rates of 2.1–8.0 writes/sec during manipulation attacks (normal baseline: ~0.2 writes/sec from PLC control loop)
3. FC 0x05/0x06 commands originating from ephemeral ports outside the expected SCADA–PLC communication pair
4. Dense FC 0x03 bursts visible in Wireshark I/O graphs, temporally correlated with attack manifest timestamps

**Impact Assessment:**
- PLC control logic overridden during manipulation attacks (pump and valve states forced to attacker-chosen values)
- Sensor readings falsified during spoofing attack, providing incorrect tank level data to SCADA operator
- PLC connection handler saturated during flood attack, degrading response time for legitimate SCADA queries
- No permanent physical process damage — simulation fail-safes and attack time-bounding prevented catastrophic states

**Detection Gap Analysis:**
- Attacks 1–3 (command injection, oscillation, valve manipulation) operated below the 2.0 writes/sec detection threshold and were not flagged by write-rate detection. Lowering the threshold would increase detection but risks false positives from legitimate SCADA operator commands.
- CNN+LSTM inference was unable to classify flows due to persistent TCP connections on loopback preventing flow expiration. Offline accuracy (99.83%) does not translate to live detection without flow segmentation.

**Recommendations:**
1. Deploy Modbus application-layer firewall enforcing function code whitelisting (permit only FC 0x03 reads from SCADA, block unsolicited writes from unknown sources)
2. Implement Modbus/TCP authentication extensions or TLS wrapping to prevent unauthenticated command injection
3. Configure per-source write-rate thresholds tuned to expected SCADA polling intervals (e.g., 0.5 writes/sec for a 2-second control loop)
4. Deploy network segmentation isolating PLC networks from general-purpose hosts
5. Implement time-windowed flow slicing for CNN+LSTM inference to enable ML-based detection on persistent connections
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

This report presented the design and live evaluation of an AI/ML-driven Intrusion Detection System tailored for Cyber-Physical Systems security. The choice of IDS over IPS reflects the primacy of availability in CPS environments, where inline packet dropping could disrupt safety-critical control loops. The implemented system combines a 20-rule signature engine with rate-based anomaly detection and a multi-model machine learning ensemble (Random Forest, CNN+LSTM, Isolation Forest), achieving 99.73% accuracy on modern traffic (CIC-IDS2017) and 97.8% cross-era generalisation across three datasets spanning 1999–2017.

The forensic investigation — conducted against a MiniCPS water treatment simulation with seven automated Modbus TCP attacks — validated the IDS's detection capabilities using NIST SP 800-86 methodology. The investigation captured 38,592 packets and 72,422 IDS alerts, with the flood detector and write-rate detector correctly identifying DoS and manipulation attacks. The CNN+LSTM model, despite 99.83% offline accuracy, highlighted a real-world deployment gap: flow-based ML inference requires flow segmentation strategies for persistent connections. This finding underscores that offline ML accuracy alone is insufficient — live deployment demands protocol-aware feature engineering matched to the target environment's traffic patterns.

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

---

**Word Count:** Approximately 3,000 words

**Appendices (to include separately):**
- Appendix A: Source Code Repository (GitHub link)
- Appendix B: ML Model Training Scripts
- Appendix C: Snort Configuration Rules
- Appendix D: Sample Forensic Artefacts

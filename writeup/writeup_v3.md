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

The forensic investigation examines three simulated attack scenarios targeting the CPS environment — a water treatment plant testbed built with Arduino PLCs communicating over Modbus RTU/TCP:

**Scenario 1: Man-in-the-Middle (MITM) Attack**

An attacker positions themselves between a SCADA master station and field PLCs, intercepting and potentially modifying Modbus communications. The attack exploits the lack of authentication in Modbus TCP, allowing the attacker to:
- Intercept sensor readings, providing false data to operators
- Inject malicious commands to actuators
- Record operational data for reconnaissance

This scenario is implemented as a Stuxnet-style async MitM proxy that operates in intermittent attack cycles (20-second intervals, 8-second active duration), manipulating actuator commands while falsifying sensor readings sent back to the SCADA system — making the attack difficult to detect through casual monitoring.

**Scenario 2: Denial of Service (DoS) Attack**

A volumetric attack floods the CPS network with traffic, overwhelming communication channels between control systems and field devices. Techniques include:
- SYN flood attacks against Modbus TCP servers
- Amplification attacks exploiting broadcast protocols
- Application-layer attacks targeting HMI web interfaces
- Modbus function code flooding to exhaust PLC connection tables

**Scenario 3: Ransomware Infection**

Ransomware infiltrates the CPS environment through phishing or supply chain compromise, encrypting:
- Engineering workstation files containing PLC configurations
- Historical data archives and logs
- HMI application files

### 3.2 Forensic Tools and Methodology

**Tools Employed:**

1. **Wireshark:** Network protocol analyser for capturing and examining packet-level traffic. Used to identify anomalous communication patterns in Modbus TCP traffic, extract malicious payloads, and reconstruct attack timelines.

2. **Snort:** Open-source network IDS/IPS configured in logging mode to generate alerts and capture traffic matching attack signatures. When configured in NIDS mode, Snort can alert on activities such as host discovery and port scanning. Provides corroborating evidence of intrusion activities.

3. **Volatility:** Memory forensics framework for analysing RAM dumps from compromised systems. Used to identify malware processes, extract encryption keys, and recover artefacts unavailable on disk.

4. **Autopsy:** Digital forensics platform for disk image analysis. Enables recovery of deleted files, timeline analysis, and keyword searching across file systems.

5. **NetworkMiner:** Network forensic analyser for extracting files, images, and credentials from captured traffic.

**Forensic Methodology:**

The investigation follows the NIST SP 800-86 guidelines for integrating forensic techniques into incident response:

1. **Collection:** Acquire volatile data (memory, network connections) before non-volatile data (disk images). Maintain chain of custody documentation. Live acquisition captures running processes and network state; dead acquisition captures disk images bit-for-bit preserving slack space and deleted file remnants.

2. **Examination:** Apply forensic tools to extract relevant data from collected evidence.

3. **Analysis:** Correlate findings across evidence sources to reconstruct attack sequences.

4. **Reporting:** Document findings, methodology, and conclusions in a structured incident report.

### 3.3 Forensic Analysis

**MITM Attack Analysis:**

Network capture analysis in Wireshark revealed:
- ARP spoofing packets linking the attacker's MAC address to the PLC's IP address
- Duplicate Modbus transaction IDs indicating intercepted and replayed traffic
- Timing anomalies showing increased latency in command-response cycles
- Modified register values in Modbus Write Multiple Registers (function code 16) commands

**DoS Attack Analysis:**

Traffic analysis identified:
- SYN packets at rates exceeding 10,000 per second from spoofed source addresses
- Connection table exhaustion on the Modbus server (half-open connections)
- Correlated PLC communication failures in SCADA logs
- Characteristic traffic patterns matching known DDoS tools

**Ransomware Analysis:**

Memory forensics using Volatility revealed:
- Malicious process injection into legitimate system processes
- Encryption routine artefacts in memory
- Command and control (C2) server IP addresses
- Registry modifications for persistence

Disk analysis using Autopsy identified:
- Encrypted files with characteristic ransomware extension modifications
- Ransom note files dropped in multiple directories
- Shadow copy deletion commands in event logs
- Initial infection vector through malicious email attachment

### 3.4 AI/ML in Forensic Analysis

Machine learning techniques enhance forensic investigation capabilities:

**Malware Classification:**

A trained classifier categorises malware samples based on behavioural features:
- API call sequences extracted from dynamic analysis
- Network communication patterns
- File system modifications
- Registry changes

Random Forest and CNN models trained on malware family datasets achieve classification accuracy exceeding 95% for known families.

**Anomaly Detection in Logs:**

LSTM networks analyse system and application logs to identify anomalous sequences indicating compromise:
- Unusual process execution chains
- Abnormal user authentication patterns
- Atypical network connection sequences

**Forensic Log Analysis:**

Natural Language Processing (NLP) techniques parse unstructured log data:
- Named Entity Recognition (NER) extracts IP addresses, usernames, and file paths
- Clustering groups related events across disparate log sources
- Timeline reconstruction automates event correlation

### 3.5 Incident Report

**INCIDENT REPORT: CPS Security Breach**

**Executive Summary:**
The CPS environment experienced a multi-vector attack comprising MITM interception, DoS disruption, and ransomware deployment. The attack resulted in temporary loss of process visibility, communication disruption, and encryption of engineering workstation data.

**Attack Timeline:**
| Time | Event |
|------|-------|
| T+0:00 | Initial phishing email delivered to engineering workstation |
| T+0:15 | User executes malicious attachment |
| T+0:20 | Malware establishes C2 communication |
| T+1:00 | Attacker conducts network reconnaissance |
| T+2:00 | ARP spoofing initiated for MITM positioning |
| T+2:30 | Modbus traffic interception begins |
| T+4:00 | DoS attack launched against SCADA server |
| T+4:15 | Ransomware deployment to engineering workstation |
| T+4:30 | Encryption of local files completed |

**Identified Anomalies:**
1. Unusual outbound connections to unknown IP addresses
2. ARP table inconsistencies across network devices
3. Elevated network traffic volumes during attack window
4. Process injection in system services
5. Mass file modification events on engineering workstation

**Impact Assessment:**
- Process visibility lost for 45 minutes during DoS attack
- Engineering workstation data encrypted (recovered from backups)
- Potential data exfiltration of PLC configurations
- No physical process damage due to fail-safe mechanisms

**Mitigation Steps Taken:**
1. Isolated affected network segments
2. Terminated malicious processes
3. Restored systems from verified backups
4. Implemented emergency Modbus authentication
5. Deployed additional network monitoring

**Recommendations:**
1. Implement network segmentation between IT and OT networks
2. Deploy protocol-aware firewalls for industrial protocols
3. Enable Modbus/TCP authentication extensions
4. Implement endpoint detection and response (EDR) on engineering workstations
5. Conduct regular security awareness training
6. Establish offline backup procedures for critical configurations
7. Deploy the AI/ML-based IDS system for continuous monitoring

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

This report presented the design of an AI/ML-driven Intrusion Detection System tailored for Cyber-Physical Systems security. The choice of IDS over IPS reflects the primacy of availability in CPS environments, where inline packet dropping could disrupt safety-critical control loops. The implemented system combines traditional signature-based detection with a multi-model machine learning ensemble (Random Forest, CNN+LSTM, Isolation Forest), achieving 99.73% accuracy on modern traffic (CIC-IDS2017) and 97.8% cross-era generalisation across three datasets spanning 1999–2017.

The forensic investigation of simulated MITM, DoS, and ransomware attacks — conducted against an Arduino-based water treatment plant testbed communicating over Modbus RTU/TCP — demonstrated the application of established forensic methodologies (NIST SP 800-86) and tools (Wireshark, Volatility, Autopsy), enhanced by AI/ML techniques for malware classification and log analysis. The integration of intelligent security monitoring with robust forensic capabilities provides a comprehensive approach to protecting critical CPS infrastructure against evolving cyber threats.

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

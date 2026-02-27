# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

University coursework (CITY3116) for Advanced Computer Forensics & Security. Two main deliverables:

1. **Task 1 (50%)**: AI/ML-driven IDS/IPS for Cyber-Physical Systems — implemented in Rust (`cps-ids/`)
2. **Task 2 (50%)**: Forensic investigation & incident response using a deliberately vulnerable web app (`website/`) with OWASP Top 10 2025 demonstrations

The writeup is a 3000-word technical report (`writeup/`).

## Commands

### CPS-IDS (Rust workspace)

```bash
# Build
cd cps-ids && cargo build

# Run tests
cd cps-ids && cargo test

# Run a single crate's tests
cd cps-ids && cargo test -p ids-engine

# Download NSL-KDD training dataset
cd cps-ids && ./scripts/download_dataset.sh
```

### Vulnerable Web App (Node.js)

```bash
cd website && npm install
cd website && npm run init-db    # initialize SQLite database with sample data
cd website && npm start           # http://localhost:3000
cd website && npm run dev         # auto-reload via nodemon
```

## Architecture

### cps-ids — Rust Workspace

A modular IDS/IPS built as a Cargo workspace with six crates:

| Crate | Purpose |
|-------|---------|
| `ids-common` | Shared types (`NetworkEvent`, `Alert`, `Severity`), config parsing, error types |
| `ids-collector` | Data ingestion — network packet capture (pcap), CPS protocol parsers (Modbus, DNP3, OPC-UA), and host-based collectors (file integrity, process monitor, log watcher, syscall monitor) |
| `ids-preprocess` | Feature extraction, normalization (min-max/z-score), label encoding, SMOTE oversampling, NSL-KDD dataset loader |
| `ids-engine` | Detection — rule-based engine, Random Forest, Isolation Forest, and ensemble voting. Also includes model evaluation metrics |
| `ids-response` | Alert actions — logging, IP blocking (iptables/nftables), SIEM forwarding (syslog), alerter |
| `ids-dashboard` | Web UI (Axum) with WebSocket for real-time alerts, REST API for stats |

Configuration lives in `config.toml` at the workspace root. The detection ensemble weights (RF 0.35, LSTM 0.40, IForest 0.25) and confidence threshold are set there.

Data pipeline: Collector → Preprocessor → Engine (rules + ML ensemble) → Response → Dashboard

### website — VulnShop

An intentionally vulnerable Express.js app (SQLite backend) demonstrating all OWASP Top 10 2025 categories. `server.js` contains all API routes with labelled vulnerabilities (A01–A10). The `OSWAP-levels/` directory has standalone HTML challenge pages for each vulnerability category.

**This app is intentionally insecure — do not "fix" vulnerabilities unless explicitly asked.**

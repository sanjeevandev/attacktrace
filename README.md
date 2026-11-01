# ▲ ATTACKTRACE

[![CI/CD Pipeline](https://github.com/sanjeevandev/attacktrace/actions/workflows/ci.yml/badge.svg)](https://github.com/sanjeevandev/attacktrace/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20Enterprise-orange.svg)](https://attack.mitre.org/)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20Clean-emerald.svg)](https://github.com/PyCQA/bandit)
[![Code Style: Flake8](https://img.shields.io/badge/Code%20Style-Flake8%20Clean-black.svg)](https://flake8.pycqa.org/)

**ATTACKTRACE** is an open-source, global command-line cybersecurity tool and dark SOC console that reconstructs end-to-end multi-stage cyber campaigns from raw telemetry. By correlating events through dual-bounded sliding temporal windows and mapping indicators to MITRE ATT&CK Enterprise tactics, ATTACKTRACE eliminates alert fatigue, delivers instant interactive time-travel attack replay, compiles multi-format forensic dossiers, and generates atomic, reversible SOAR containment playbooks.

---

## 1. Key Capabilities & Innovations

* **⏱️ Time-Travel Attack Replayer**: Interactive SOC timeline scrubber that dynamically filters D3 topology nodes and causal links in real time, pulsing an animated radar ring around the newest adversary movement at each kill-chain step.
* **🌐 Multi-Format Real Telemetry Ingestion**: Memory-efficient line-by-line streaming parser for `.jsonl` (preventing OOM on large datasets), RFC 3164/5424 Syslog, Windows Security Event Logs (Event IDs 4624, 4625, 4688, 4672), and Apache/Nginx Web Server Access Logs with automatic URL parameter decoding.
* **🎛️ Multi-Platform Breach Scenarios**: Built-in synthetic cyber attacks simulating:
  - 🪟 **Windows AD Compromise**: Kerberoasting $\rightarrow$ Encoded PowerShell $\rightarrow$ NTDS.dit Active Directory dump.
  - 🐧 **Linux Server Breach**: Web reconnaissance $\rightarrow$ SQL injection $\rightarrow$ Sudoers privilege escalation $\rightarrow$ credential exfiltration.
  - 🍏 **macOS Endpoint Intrusion**: AppleScript / osascript execution $\rightarrow$ LaunchAgent persistence $\rightarrow$ Keychain credential dumping.
* **🛡️ Atomic SOAR Rollbacks**: Generates defensive remediation scripts (`mitigate.sh` or `mitigate.ps1`) alongside cryptographic SHA-256 reverse rollback scripts (`rollback.sh` or `rollback.ps1`) to safely unban IPs, restore access, and prevent collateral disruption.
* **📦 Triple Forensic Dossier Export**: Instant 1-click downloads for:
  1. 📄 **Executive Markdown Report** (`INCIDENT_REPORT.md`): Full human-readable investigation dossier.
  2. 📦 **Machine-Readable JSON Dossier** (`dossier.json`): Structured telemetry with SHA-256 cryptographic hashes.
  3. 🗺️ **Official MITRE ATT&CK Navigator Layer** (`navigator.json`): Compatible with ATT&CK Navigator v4.5.
* **🔒 Clean Demo Data Isolation**: Zero risk of contaminating production SQLite data. Demo records are tagged with `is_demo=1` and can be purged at any time without impacting real ingested events.

---

## 2. Installation

### Option A: Global Installation via `pipx` (Recommended)
Install globally as an isolated CLI tool on any platform (Linux, macOS, Windows):
```bash
pipx install git+https://github.com/sanjeevandev/attacktrace.git
```

### Option B: Local Editable Installation (Development)
```bash
git clone https://github.com/sanjeevandev/attacktrace.git
cd attacktrace
python -m venv venv

# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e .
```

Verify installation:
```bash
attacktrace --version
```

---

## 3. Operational Modes: Demo vs. Real

ATTACKTRACE operates under two strictly separated execution paradigms:

| Dimension | Demo Mode (`attacktrace demo`) | Real Mode (`attacktrace ingest <file>`) |
|---|---|---|
| **Data Source** | Built-in multi-platform scenarios (`windows`, `linux`, `macos`) | Real-world telemetry (`.json`, `.jsonl`, `.log`, `.syslog`) |
| **Storage Tagging** | `is_demo = 1` | `is_demo = 0` with complete file provenance |
| **Purgeable** | Yes, via `attacktrace demo --reset` or SOC UI button | Preserved permanently in SQLite history |
| **SOC Console Pill** | Amber `[DEMO MODE]` badge | Emerald `[REAL MODE]` badge |

---

## 4. CLI Reference & Usage

ATTACKTRACE provides a modular, command-line interface inspired by Nmap and Burp Suite.

### 4.1. Global System & Database Status
Inspect SQLite storage location, total ingested events, incident breakdown, and severity metrics:
```bash
attacktrace status
```
```text
================================================================================
  ▲  A T T A C K T R A C E   |   Cybersecurity Threat Reconstruction Engine
================================================================================
┌──────────────────────────────────────────────────────────────────────────────┐
│                   D A T A B A S E   &   S Y S T E M   S T A T U S            │
└──────────────────────────────────────────────────────────────────────────────┘
  Database Path:        ~/.attacktrace/attacktrace.db
  Storage Size:         480.00 KB
  Total Log Events:     345
  Total Incidents:      4 (1 real, 3 demo)
  Max Risk Score:       100
  Severity Breakdown:
    - CRITICAL          : 3
    - HIGH              : 1
────────────────────────────────────────────────────────────────────────────────
```

### 4.2. Ingesting Real Telemetry (`attacktrace ingest`)
Ingest and correlate real log files with automatic format detection:
```bash
# Auto-detect format (.jsonl, .syslog, Apache/Nginx web logs, Windows events)
attacktrace ingest /var/log/auth.log

# Ingest line-by-line JSONL streaming with custom 60-min window
attacktrace ingest /data/siem_export.jsonl --type jsonl --window 60

# Ingest Windows EVTX JSON exports
attacktrace ingest /data/SecurityEvents.json --type windows
```

### 4.3. Multi-Platform Breach Simulation (`attacktrace demo`)
Simulate synthetic attacks across diverse operating systems:
```bash
# Windows AD Compromise (Kerberoasting -> PowerShell -> NTDS dump)
attacktrace demo --scenario windows

# Linux Server Breach (Web recon -> SQLi -> Sudoers -> Exfil)
attacktrace demo --scenario linux

# macOS Endpoint Intrusion (AppleScript -> LaunchAgent -> Keychain dump)
attacktrace demo --scenario macos

# Cleanly purge all demo records from SQLite
attacktrace demo --reset
```

### 4.4. Incident Investigation (`attacktrace incidents`)
List correlated incidents or inspect a specific attack path:
```bash
# List all correlated incidents
attacktrace incidents --list

# Deep-dive into an incident with full chronological audit trail
attacktrace incidents --id INC-2026-001

# Output raw JSON incident details
attacktrace incidents --id INC-2026-001 --json
```

### 4.5. Forensic Report Compilation (`attacktrace report`)
Export forensic investigation dossiers in multiple industry-standard formats:
```bash
# Generate Executive Markdown report (default: INCIDENT_REPORT.md)
attacktrace report --id INC-2026-001 --format markdown

# Generate Machine-Readable Forensic JSON Dossier (dossier.json)
attacktrace report --id INC-2026-001 --format json --output /tmp/dossier.json

# Generate Official MITRE ATT&CK Navigator Layer (navigator.json)
attacktrace report --id INC-2026-001 --format navigator --output /tmp/layer.json
```

### 4.6. SOAR Containment & Rollback Generation (`attacktrace mitigate`)
Generate OS-native remediation scripts or reverse rollback scripts:
```bash
# Generate containment script (mitigate.sh or mitigate.ps1)
attacktrace mitigate --id INC-2026-001 --platform linux

# Generate reverse rollback script backed by SHA-256 tokens
attacktrace mitigate --id INC-2026-001 --platform linux --rollback
```

### 4.7. Web SOC Console & WebSocket Hub (`attacktrace serve`)
Launch the dark SOC console, live WebSocket streaming hub, and REST API:
```bash
attacktrace serve --host 127.0.0.1 --port 8000
```
* **SOC Console**: `http://127.0.0.1:8000/dashboard`
* **Swagger API Docs**: `http://127.0.0.1:8000/docs`
* **Live WebSocket Feed**: `ws://127.0.0.1:8000/ws/alerts`

---

## 5. Architectural Pipeline

```text
                                [ MULTI-FORMAT TELEMETRY ]
                     (JSON, JSONL, RFC Syslog, Windows Events, Web Logs)
                                             │
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │ LAYER 1: MULTI-FORMAT ADAPTERS & INGESTION ENGINE                                     │
 │ - WindowsEventAdapter, SyslogAdapter, WebLogAdapter, streaming JSONL generator        │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ (Normalized UnifiedEvent)
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │ LAYER 2: PARSER & HEURISTIC MITRE ENRICHMENT                                          │
 │ - MITRE ATT&CK Enterprise TTP signatures & calibrated threat indicators               │
 │ - Dynamic risk calculation (0-100) and severity classification                        │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ (EnrichedSecurityEvent)
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │ LAYER 3: DUAL-BOUNDED SLIDING WINDOW CORRELATION                                      │
 │ - Actor (IP) grouping with 60-min sliding window & 240-min max campaign bounds        │
 │ - Graph reconstruction & incident confidence score calculation                        │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ (AttackIncident)
 ┌───────────────────────────────────────────▼───────────────────────────────────────────┐
 │ LAYER 4: SQLITE PERSISTENCE & CLEAN DEMO ISOLATION                                    │
 │ - Relational schema: events, enriched_events, incidents, attack_steps, soar_actions   │
 │ - Strict isolation: is_demo=1 (purgeable) vs is_demo=0 (permanent)                    │
 └───────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │
             ┌───────────────────────────────┴───────────────────────────────┐
             ▼                                                               ▼
 ┌───────────────────────────────────────────┐   ┌───────────────────────────────────────────┐
 │ LAYER 5: SOAR ORCHESTRATION & REPORTING   │   │ LAYER 6: FASTAPI, WEBSOCKETS & DARK SOC   │
 │ - Cross-platform containment & rollbacks  │   │ - Live alert streaming hub                │
 │ - Markdown reports, JSON dossiers,        │   │ - D3 Topology Graph & Time-Travel         │
 │   and MITRE ATT&CK Navigator v4.5 layers  │   │   Attack Replayer with radar pulse        │
 └───────────────────────────────────────────┘   └───────────────────────────────────────────┘
```

---

## 6. Testing & CI/CD Matrix

ATTACKTRACE maintains an exhaustive automated test suite with **100% pass rate** (137+ tests) across Linux, macOS, and Windows on Python 3.10 through 3.13:

```bash
# Run full unit and integration test suite
pytest -v

# Run Flake8 linter
flake8 src/ tests/ --max-line-length=120 --extend-ignore=E203,W503

# Run Bandit security audit
bandit -r src/ -x tests/ -ll
```

---

## 7. License

This project is licensed under the [MIT License](LICENSE) — see the LICENSE file for details.

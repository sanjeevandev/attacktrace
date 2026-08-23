# ▲ ATTACKTRACE

[![CI/CD Pipeline](https://github.com/cyber-research/attacktrace/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-research/attacktrace/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Docker Image](https://img.shields.io/badge/Docker-Compatible-emerald)](https://www.docker.com/)
[![MITRE ATT&CK Mapped](https://img.shields.io/badge/MITRE%20ATT%26CK-5%20Tactics-orange)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**ATTACKTRACE** is a high-fidelity threat correlation, visualization, and SOAR response platform. By ingesting multi-source security telemetry, extracting MITRE ATT&CK tactics, and grouping events chronologically via sliding time windows, ATTACKTRACE reconstructs full attack paths to resolve the alert fatigue caused by traditional SIEM systems.

---

## 1. Architectural Layout

```text
                                  [ RAW JSON TELEMETRY STREAM ]
                                                │
 ┌──────────────────────────────────────────────▼──────────────────────────────────────────────┐
 │ LAYER 1: INGESTION ENGINE                                                                   │
 │ - UnifiedEvent canonical schema validation & cleaning                                       │
 └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                │ (Normalized Events)
 ┌──────────────────────────────────────────────▼──────────────────────────────────────────────┐
 │ LAYER 2: PARSER & ENRICHMENT                                                                │
 │ - MITRE ATT&CK TTP Mapping & signature threat indicators                                   │
 │ - Dynamic risk calculation (0-100) & severity assignment                                    │
 └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                │ (Enriched Security Events)
 ┌──────────────────────────────────────────────▼──────────────────────────────────────────────┐
 │ LAYER 3: THREAT CORRELATION & GRAPH RECONSTRUCTION                                          │
 │ - Actor (IP) and Target grouping + 60-min sliding windows                                   │
 │ - Campaign promotion thresholds & security confidence calculations                          │
 └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                │ (Correlated AttackIncidents)
 ┌──────────────────────────────────────────────┴──────────────────────────────────────────────┐
 │                                                                                             │
 ┌──────────────▼──────────────┐                                 ┌──────────────▼──────────────┐
 │ LAYER 4: INVESTIGATION API  │                                 │ LAYER 5: PLAYBOOK ENGINE    │
 │ - FastAPI REST server & docs │                                 │ - Offline IP Threat Intel   │
 │ - WebSocket alerts broadcast │                                 │ - Executable SOAR scripts   │
 │ - D3/SVG Visual Dashboard   │                                 │ - Forensic report compilers │
 └─────────────────────────────┘                                 └─────────────────────────────┘
```

---

## 2. MITRE ATT&CK Coverage Matrix

ATTACKTRACE comes equipped with out-of-the-box heuristic detection rules:

| Technique ID | Tactic Category | Signature Indicator | Detection Pattern | Risk Weight |
|---|---|---|---|---|
| **T1595** | Reconnaissance | `SUSPICIOUS_WEB_RECON` | Requests for env config back-ups (`/.env`). | 25 |
| **T1110** | Credential Access | `FAILED_AUTH_BURST` | Multi-failure login requests on portals. | 55 |
| **T1190** | Initial Access | `SQL_INJECTION_PATTERN` | Chained database query inputs (`UNION SELECT`). | 65 |
| **T1078** | Privilege Escalation | `PRIVILEGE_ESCALATION` | Unauthorized modifications to config files (e.g. `/etc/sudoers`). | 85 |
| **T1005** | Exfiltration | `UNAUTHORIZED_EXFILTRATION` | Accessing data endpoints or queries containing `SELECT`. | 80 |

---

## 3. Quickstart Guide

### 3.1. Local Installation

```bash
# 1. Setup python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Run unit & E2E tests
make test

# 3. Launch CLI reports
python3 main.py --cli

# 4. Spin up FastAPI & SOC console locally
python3 main.py --serve
```
* Access the web dashboard at `http://127.0.0.1:8000/dashboard` and swagger docs at `http://127.0.0.1:8000/docs`.

### 3.2. Docker Compose (One-Click Multi-Service Demo)
Deploy the complete multi-service stack containing the main FastAPI engine and the background attack simulator:
```bash
# Spins up engine and starts real-time log ingestion stream
make demo
```
* To tear down container stacks: `make down`

---

## 4. API Reference

| Endpoint Path | Method | Description | Sample Response Payload |
|---|---|---|---|
| `/api/v1/ingest` | `POST` | Normalizes and correlates a batch of logs. | `[{"incident_id": "...", "confidence_score": 90}]` |
| `/api/v1/incidents` | `GET` | Retrieves all cached incidents. | `[{"incident_id": "...", "primary_actor_ip": "..."}]` |
| `/api/v1/incidents/{id}/graph` | `GET` | Exports D3 network graph nodes & edges. | `{"nodes": [{"id": "..."}], "edges": [{"source": "..."}]}` |
| `/api/v1/incidents/{id}/mitigate`| `POST` | Compiles playbooks into `mitigate.sh` scripts. | `[{"action_type": "FIREWALL_BLOCK", "status": "SIMULATED"}]` |
| `/api/v1/incidents/{id}/report`  | `GET`  | Compiles executive forensic Markdown report. | `# ATTACKTRACE Forensic Incident Report...` |
| `/api/v1/stats` | `GET` | Returns aggregated metrics & classifications. | `{"total_ingested": 9, "critical_severity_count": 1}` |
| `/ws/alerts` | `WS` | Non-blocking alerts channel. | `{"event_id": "...", "type": "ALERT_NOTIFICATION"}` |

---

## 5. Architectural Deep-Dive
For details regarding sliding windows, risk calculations, and custom rules extensions, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

import os
import json
import pytest
from fastapi.testclient import TestClient

from src.pipeline import AttackTracePipeline
from src.threat_intel import ThreatIntelEngine
from src.playbooks import PlaybookEngine
from src.reporter import IncidentReporter
from src.api import app

client = TestClient(app)


def test_complete_e2e_pipeline():
    """
    Validates end-to-end processing across all 5 layers:
    1. Ingestion of attack scenario logs (L1)
    2. Deep parsing and TTP mappings (L2)
    3. Graph-based temporal incident correlation (L3)
    4. REST endpoints, graph models and WebSocket routes (L4)
    5. Threat reputation lookup, SOAR mitigation scripts, and forensic report generation (L5)
    """
    scenario_path = "data/attack_scenario.json"
    assert os.path.exists(scenario_path), f"Scenario file {scenario_path} must exist for E2E validation."

    # 1. Pipeline Execution (Layers 1-3)
    pipeline = AttackTracePipeline()
    incidents = pipeline.run_pipeline(scenario_path, time_window_minutes=60)

    assert len(pipeline.collector.valid_events) == 9
    assert len(pipeline.collector.dropped_events) == 0
    assert len(pipeline.enriched_events) == 9
    assert len(incidents) > 0

    primary_incident = incidents[0]
    assert primary_incident.primary_actor_ip == "185.220.101.5"
    assert "admin" in primary_incident.targeted_users
    assert "db_webapp" in primary_incident.targeted_users
    assert primary_incident.confidence_score >= 80

    # 2. Threat Intel Enrichment & SOAR Actions (Layer 5 Engines)
    ti_engine = ThreatIntelEngine()
    playbook_engine = PlaybookEngine()
    reporter = IncidentReporter()

    ti_engine.enrich_incident(primary_incident)
    assert primary_incident.threat_intel is not None
    assert primary_incident.threat_intel.country == "Germany"
    assert primary_incident.threat_intel.is_tor_exit_node is True

    actions = playbook_engine.generate_mitigations(primary_incident)
    assert len(actions) == 4
    action_types = [a.action_type for a in actions]
    assert "FIREWALL_BLOCK" in action_types
    assert "SESSION_REVOKE" in action_types
    assert "ISOLATE_HOST" in action_types

    mitigate_script_path = "test_e2e_mitigate.sh"
    playbook_engine.export_mitigation_script(actions, mitigate_script_path)
    assert os.path.exists(mitigate_script_path)
    os.remove(mitigate_script_path)

    report_path = "TEST_E2E_REPORT.md"
    reporter.generate_markdown_report(primary_incident, primary_incident.threat_intel, actions, report_path)
    assert os.path.exists(report_path)
    os.remove(report_path)

    # 3. REST API & WebSocket Integrations (Layer 4 API validation)
    with open(scenario_path, "r", encoding="utf-8") as f:
        raw_logs = json.load(f)

    # Post events through ingestion endpoint
    ingest_res = client.post("/api/v1/ingest", json=raw_logs)
    assert ingest_res.status_code == 200
    ingest_data = ingest_res.json()
    assert len(ingest_data) > 0
    assert ingest_data[0]["primary_actor_ip"] == "185.220.101.5"

    # Get incidents endpoint
    incidents_res = client.get("/api/v1/incidents")
    assert incidents_res.status_code == 200
    incidents_data = incidents_res.json()
    assert len(incidents_data) > 0
    inc_id = incidents_data[0]["incident_id"]

    # Get incident graph endpoint
    graph_res = client.get(f"/api/v1/incidents/{inc_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    
    # Get incident report endpoint
    report_res = client.get(f"/api/v1/incidents/{inc_id}/report")
    assert report_res.status_code == 200
    assert "# ATTACKTRACE Forensic Incident Report" in report_res.text

    # Post simulate stream endpoint
    stream_res = client.post("/api/v1/stream/trigger", json=raw_logs)
    assert stream_res.status_code == 200
    assert stream_res.json()["status"] == "success"

    # Check WebSocket route via handshake
    with client.websocket_connect("/ws/alerts") as ws:
        pass

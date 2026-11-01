import json
import os
import pytest
from fastapi.testclient import TestClient

from src.api import app, pipeline, ti_engine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def ensure_sample_data():
    """Ensure at least one incident is ingested so API routes have data."""
    scenario_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "attack_scenario.json",
    )
    if not pipeline.incidents:
        pipeline.run_pipeline(scenario_path)
        for inc in pipeline.incidents:
            ti_engine.enrich_incident(inc)


def test_dashboard_serves_html(client):
    """Test that GET /dashboard returns HTTP 200 and text/html."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<!DOCTYPE html>" in response.text
    assert "ATTACKTRACE" in response.text


def test_dashboard_contains_required_dom_elements(client):
    """
    Verify HTML contains all required DOM elements:
    - Time-Travel slider (#replay-slider or #timeline-slider)
    - Scenario switcher modal (#scenario-modal)
    - Mode badge (#mode-badge, .mode-pill)
    - Export buttons (#btn-export-dossier, #btn-export-markdown, etc.)
    - Replayer controls (#replay-play, #replay-step-back, #replay-step-forward)
    """
    response = client.get("/dashboard")
    html = response.text

    # 1. Time-Travel Slider
    assert 'id="replay-slider"' in html or 'id="timeline-slider"' in html
    assert 'id="replay-play"' in html
    assert 'id="replay-step-back"' in html
    assert 'id="replay-step-forward"' in html
    assert 'id="replay-step-display"' in html
    assert 'id="replay-technique-display"' in html

    # 2. Scenario Modal
    assert 'id="scenario-modal"' in html
    assert 'id="btn-select-scenario"' in html
    assert 'Windows AD Compromise' in html
    assert 'Linux Server Breach' in html
    assert 'macOS Endpoint Intrusion' in html

    # 3. Mode Badge & Pulse Status
    assert 'id="mode-badge"' in html
    assert 'mode-pill' in html
    assert 'id="ws-status-badge"' in html
    assert 'id="status-dot"' in html

    # 4. Export Buttons
    assert 'id="btn-export-dossier"' in html
    assert 'id="btn-export-markdown"' in html
    assert 'id="btn-export-navigator"' in html
    assert 'id="btn-export-mitigate"' in html
    assert 'id="btn-export-rollback"' in html

    # 5. Radar Pulse styling
    assert 'radar-ring' in html
    assert 'radar-ripple' in html


def test_dashboard_embedded_d3_and_svg_structure(client):
    """Test that D3 library and SVG topology elements are properly integrated."""
    response = client.get("/dashboard")
    html = response.text

    # D3 library script reference
    assert "d3.v7.min.js" in html or "d3" in html

    # SVG Canvas structure
    assert 'id="graph-svg"' in html
    assert 'id="edges-group"' in html
    assert 'id="nodes-group"' in html
    assert 'id="svg-host"' in html

    # Core client-side graph functions
    assert "drawSVG" in html
    assert "applyGraphStepFilter" in html
    assert "onReplaySliderChange" in html


def test_all_dashboard_backing_api_routes(client):
    """Verify that every REST endpoint backing the dashboard responds cleanly."""
    # 1. Stats
    res_stats = client.get("/api/v1/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_ingested" in stats
    assert "total_incidents" in stats

    # 2. Incidents List
    res_inc = client.get("/api/v1/incidents")
    assert res_inc.status_code == 200
    incidents = res_inc.json()
    assert len(incidents) >= 1
    incident_id = incidents[0]["incident_id"]

    # 3. Demo Scenarios List
    res_scenarios = client.get("/api/v1/demo/scenarios")
    assert res_scenarios.status_code == 200
    scenarios = res_scenarios.json()
    assert len(scenarios) >= 3
    scenario_names = [s["name"] for s in scenarios]
    assert "windows_ad_compromise" in scenario_names
    assert "linux_server_breach" in scenario_names
    assert "macos_endpoint_intrusion" in scenario_names

    # 4. Load Demo Scenario
    res_load = client.post("/api/v1/demo/load/windows_ad_compromise")
    assert res_load.status_code == 200
    load_data = res_load.json()
    assert load_data["status"] == "success"
    assert load_data["scenario"] == "windows_ad_compromise"

    # Refresh active incident ID after loading scenario
    res_inc2 = client.get("/api/v1/incidents")
    assert res_inc2.status_code == 200
    incidents2 = res_inc2.json()
    assert len(incidents2) >= 1
    incident_id = incidents2[0]["incident_id"]

    # 5. Incident Graph Topology
    res_graph = client.get(f"/api/v1/incidents/{incident_id}/graph")
    assert res_graph.status_code == 200
    graph = res_graph.json()
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) > 0

    # 6. Forensic Markdown Report
    res_report = client.get(f"/api/v1/incidents/{incident_id}/report")
    assert res_report.status_code == 200
    assert "ATTACKTRACE Forensic Incident Report" in res_report.text

    # 7. Forensic JSON Dossier
    res_dossier = client.get(f"/api/v1/incidents/{incident_id}/dossier")
    assert res_dossier.status_code == 200
    dossier = res_dossier.json()
    assert dossier["schema_version"] == "1.0"
    assert "kill_chain_steps" in dossier

    # 8. MITRE Navigator Layer
    res_nav = client.get(f"/api/v1/incidents/{incident_id}/navigator")
    assert res_nav.status_code == 200
    nav = res_nav.json()
    assert nav["domain"] == "enterprise-attack"

    # 9. Rollback Script
    res_rbk = client.get(f"/api/v1/incidents/{incident_id}/rollback-script")
    assert res_rbk.status_code == 200
    assert len(res_rbk.text) > 0

    # 10. Mitigation Actions
    res_mit = client.post(f"/api/v1/incidents/{incident_id}/mitigate")
    assert res_mit.status_code == 200
    assert isinstance(res_mit.json(), list)

    # 11. Reset Demo State
    res_reset = client.post("/api/v1/demo/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "success"

import json
import os
import pytest
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)


def test_stats_endpoint():
    """
    Checks that the stats endpoint returns the correct fields and status.
    """
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_ingested" in data
    assert "total_dropped" in data
    assert "total_incidents" in data
    assert "max_risk" in data
    assert "mitre_techniques" in data
    assert "severity_distribution" in data


def test_ingest_and_get_incidents():
    """
    Ingests attack logs via POST, retrieves the list of incidents,
    queries a specific incident detail, and fetches its graph topology.
    """
    # Load scenario logs
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")
    with open(scenario_path, "r", encoding="utf-8") as f:
        logs = json.load(f)

    # Ingest logs
    response = client.post("/api/v1/ingest", json=logs)
    assert response.status_code == 200
    incidents = response.json()
    assert len(incidents) >= 1
    
    # Get all incidents
    get_res = client.get("/api/v1/incidents")
    assert get_res.status_code == 200
    assert len(get_res.json()) >= 1
    
    # Get specific incident by ID
    inc_id = incidents[0]["incident_id"]
    det_res = client.get(f"/api/v1/incidents/{inc_id}")
    assert det_res.status_code == 200
    assert det_res.json()["incident_id"] == inc_id

    # Get incident graph topology
    graph_res = client.get(f"/api/v1/incidents/{inc_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert len(graph_data["nodes"]) > 0


def test_incident_not_found():
    """
    Queries details and graphs of a non-existent incident ID and expects a 404 response.
    """
    response = client.get("/api/v1/incidents/invalid-uuid-format")
    assert response.status_code == 404

    graph_res = client.get("/api/v1/incidents/invalid-uuid-format/graph")
    assert graph_res.status_code == 404


def test_dashboard_endpoint():
    """
    Verifies that the /dashboard route serves the interactive SOC console.
    """
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "ATTACKTRACE" in response.text

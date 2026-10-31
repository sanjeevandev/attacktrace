import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.db import DatabaseManager
from src.demo_manager import ScenarioManager
from src.models import KillChainStage, SeverityLevel


@pytest.fixture
def temp_db():
    db = DatabaseManager(":memory:")
    yield db
    db.close()


@pytest.fixture
def scenario_mgr():
    return ScenarioManager()


def test_list_available_scenarios(scenario_mgr):
    """
    Verifies that all three multi-platform scenarios are discovered
    with valid metadata (name, platform, description, event_count).
    """
    scenarios = scenario_mgr.list_available_scenarios()
    assert len(scenarios) >= 3

    scenario_names = {s["name"]: s for s in scenarios}
    assert "windows_ad_compromise" in scenario_names
    assert "linux_server_breach" in scenario_names
    assert "macos_endpoint_intrusion" in scenario_names

    # Check platforms
    assert scenario_names["windows_ad_compromise"]["platform"] == "Windows"
    assert scenario_names["linux_server_breach"]["platform"] == "Linux"
    assert scenario_names["macos_endpoint_intrusion"]["platform"] == "macOS"

    # Check event counts
    for s in scenarios:
        assert s["event_count"] >= 4
        assert len(s["description"]) > 10


def test_load_and_validate_all_scenarios(scenario_mgr):
    """
    Tests loading of all 3 scenario files, confirming every event has is_demo=True
    and all required core event attributes.
    """
    for sc_name in ["windows_ad_compromise", "linux_server_breach", "macos_endpoint_intrusion"]:
        records = scenario_mgr.load_scenario(sc_name)
        assert len(records) >= 4

        for rec in records:
            assert rec["is_demo"] is True
            assert "timestamp" in rec
            assert "source_type" in rec
            assert "event_type" in rec
            assert "source_ip" in rec


def test_run_scenario_windows(scenario_mgr, temp_db):
    """
    Tests end-to-end execution of the Windows AD compromise scenario:
    Kerberoasting (T1110) -> RDP logon (T1078) -> PowerShell execution (T1059.001)
    -> Token elevation (T1548) -> NTDS credential dumping (T1005).
    """
    incidents = scenario_mgr.run_scenario("windows_ad_compromise", db=temp_db)
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc.primary_actor_ip == "198.51.100.45"
    assert "jdoe" in inc.targeted_users
    assert len(inc.stages_detected) >= 2
    assert inc.threat_intel is not None
    assert inc.threat_intel.threat_actor_category == "Brute Force Botnet"

    # Verify persisted in database
    db_incidents = temp_db.get_incidents(is_demo=True)
    assert len(db_incidents) >= 1
    assert db_incidents[0].incident_id == inc.incident_id


def test_run_scenario_linux(scenario_mgr, temp_db):
    """
    Tests end-to-end execution of the Linux server breach scenario:
    Web recon (T1595) -> SQLi (T1190) -> Sudoers priv esc (T1548) -> Table exfiltration (T1005).
    """
    incidents = scenario_mgr.run_scenario("linux_server_breach", db=temp_db)
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc.primary_actor_ip == "203.0.113.195"
    assert len(inc.stages_detected) >= 2
    assert inc.overall_severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert inc.threat_intel is not None


def test_run_scenario_macos(scenario_mgr, temp_db):
    """
    Tests end-to-end execution of the macOS endpoint intrusion scenario:
    osascript execution (T1059.002) -> LaunchAgents persistence (T1543.001)
    -> Keychain query (T1555.001) -> Outbound exfiltration (T1048).
    """
    incidents = scenario_mgr.run_scenario("macos_endpoint_intrusion", db=temp_db)
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc.primary_actor_ip == "192.0.2.77"
    assert len(inc.stages_detected) >= 2
    assert inc.overall_severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]


def test_reset_demo_state(scenario_mgr, temp_db):
    """
    Verifies that reset_demo_state cleanly purges demo data without errors.
    """
    # Run scenario into DB
    scenario_mgr.run_scenario("windows_ad_compromise", db=temp_db)
    assert len(temp_db.get_incidents(is_demo=True)) >= 1

    # Purge demo state
    result = scenario_mgr.reset_demo_state(temp_db)
    assert result["incidents_deleted"] >= 1
    assert len(temp_db.get_incidents(is_demo=True)) == 0


def test_api_demo_routes():
    """
    Verifies the demo API endpoints in src/api.py:
    1. GET /api/v1/demo/scenarios
    2. POST /api/v1/demo/load/{scenario_name}
    3. POST /api/v1/demo/reset
    """
    client = TestClient(app)

    # 1. List scenarios
    res_list = client.get("/api/v1/demo/scenarios")
    assert res_list.status_code == 200
    scenarios = res_list.json()
    assert len(scenarios) >= 3

    # 2. Load Linux scenario
    res_load = client.post("/api/v1/demo/load/linux_server_breach")
    assert res_load.status_code == 200
    load_data = res_load.json()
    assert load_data["status"] == "success"
    assert load_data["incidents_created"] >= 1

    # 3. Check incidents retrieved through API
    res_incs = client.get("/api/v1/incidents")
    assert res_incs.status_code == 200
    assert len(res_incs.json()) >= 1

    # 4. Non-existent scenario returns 404
    res_not_found = client.post("/api/v1/demo/load/non_existent_os_exploit")
    assert res_not_found.status_code == 404

    # 5. Reset demo state
    res_reset = client.post("/api/v1/demo/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "success"

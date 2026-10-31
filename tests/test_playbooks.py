import os
import pytest
from src.threat_intel import ThreatIntelEngine
from src.playbooks import PlaybookEngine
from src.reporter import IncidentReporter
from src.models import AttackIncident, SeverityLevel, KillChainStage, AttackStep


@pytest.fixture
def mock_incident():
    # Construct a high severity incident for playbook testing
    step1 = AttackStep(
        stage=KillChainStage.RECONNAISSANCE,
        timestamp="2026-08-23T17:40:00Z",
        technique="T1595 - Active Scanning",
        description="Scanning ports",
        actor="185.220.101.5",
        risk_score=25
    )
    step2 = AttackStep(
        stage=KillChainStage.EXFILTRATION,
        timestamp="2026-08-23T17:44:00Z",
        technique="T1048 - Exfiltration Over Alternative Protocol",
        description="Exfiltrated database tables",
        actor="185.220.101.5",
        risk_score=95
    )
    return AttackIncident(
        primary_actor_ip="185.220.101.5",
        targeted_users=["admin"],
        start_time="2026-08-23T17:40:00Z",
        end_time="2026-08-23T17:44:00Z",
        overall_severity=SeverityLevel.CRITICAL,
        confidence_score=90,
        stages_detected=[KillChainStage.RECONNAISSANCE, KillChainStage.EXFILTRATION],
        steps=[step1, step2]
    )


def test_threat_intel_resolution():
    ti_engine = ThreatIntelEngine()
    
    # German malicious Tor IP
    tor_ip_data = ti_engine.lookup_ip("185.220.101.5")
    assert tor_ip_data.ip == "185.220.101.5"
    assert tor_ip_data.reputation_score == 95
    assert tor_ip_data.country == "Germany"
    assert tor_ip_data.is_tor_exit_node is True

    # Private IP check (heuristics)
    local_ip_data = ti_engine.lookup_ip("192.168.1.15")
    assert local_ip_data.reputation_score == 0
    assert local_ip_data.country == "Private/Internal"
    assert local_ip_data.threat_actor_category == "Clean"

    # Public unknown IP check (defaults)
    unknown_ip_data = ti_engine.lookup_ip("8.8.8.8")
    assert unknown_ip_data.reputation_score == 15
    assert unknown_ip_data.threat_actor_category == "Clean"


def test_playbook_generation(mock_incident):
    engine = PlaybookEngine()
    actions = engine.generate_mitigations(mock_incident, platform="linux")
    
    # Assert generated mitigations count and type
    assert len(actions) == 3
    action_types = [act.action_type for act in actions]
    assert "FIREWALL_BLOCK" in action_types
    assert "SESSION_REVOKE" in action_types
    assert "ISOLATE_HOST" in action_types

    # Assert command content
    fw_action = next(act for act in actions if act.action_type == "FIREWALL_BLOCK")
    assert "iptables" in fw_action.command_snippet
    assert "185.220.101.5" in fw_action.command_snippet

    session_action = next(act for act in actions if act.action_type == "SESSION_REVOKE")
    assert "admin" in session_action.command_snippet

    isolate_action = next(act for act in actions if act.action_type == "ISOLATE_HOST")
    assert "eth0 down" in isolate_action.command_snippet

    # Verify mitigation script generation
    script_path = "test_mitigate.sh"
    script_content = engine.export_mitigation_script(actions, script_path, platform="linux")
    assert os.path.exists(script_path)
    assert "#!/bin/bash" in script_content
    assert "iptables" in script_content
    assert "ROLLBACK PROCEDURES" in script_content
    
    # Clean up
    if os.path.exists(script_path):
        os.remove(script_path)


def test_cross_platform_windows_mitigations(mock_incident):
    """
    Tests SOAR mitigation and rollback generation for Windows PowerShell.
    """
    engine = PlaybookEngine()
    actions = engine.generate_mitigations(mock_incident, platform="windows")
    assert len(actions) == 3

    # 1. Firewall block
    fw = next(act for act in actions if act.action_type == "FIREWALL_BLOCK")
    assert "New-NetFirewallRule" in fw.command_snippet
    assert "ATTACKTRACE_BLOCK_185.220.101.5" in fw.command_snippet
    assert "Remove-NetFirewallRule" in fw.rollback_snippet
    assert fw.rollback_token.startswith("RBK-")
    assert fw.status == "SIMULATED"

    # 2. Session revoke
    sess = next(act for act in actions if act.action_type == "SESSION_REVOKE")
    assert "Stop-Process" in sess.command_snippet
    assert "admin" in sess.command_snippet
    assert "account unlock required" in sess.rollback_snippet

    # 3. Host isolation
    iso = next(act for act in actions if act.action_type == "ISOLATE_HOST")
    assert "Disable-NetAdapter" in iso.command_snippet
    assert "Enable-NetAdapter" in iso.rollback_snippet

    # 4. Script export
    ps1_path = "test_mitigate.ps1"
    content = engine.export_mitigation_script(actions, ps1_path, platform="windows")
    assert os.path.exists(ps1_path)
    assert "POWERSHELL" in content
    assert "New-NetFirewallRule" in content
    assert "ROLLBACK PROCEDURES" in content
    if os.path.exists(ps1_path):
        os.remove(ps1_path)


def test_cross_platform_macos_mitigations(mock_incident):
    """
    Tests SOAR mitigation and rollback generation for macOS pfctl.
    """
    engine = PlaybookEngine()
    actions = engine.generate_mitigations(mock_incident, platform="macos")
    assert len(actions) == 3

    # 1. Firewall block (pfctl)
    fw = next(act for act in actions if act.action_type == "FIREWALL_BLOCK")
    assert "pfctl" in fw.command_snippet
    assert "185.220.101.5" in fw.command_snippet
    assert "pfctl -a attacktrace -F rules" in fw.rollback_snippet
    assert fw.rollback_token.startswith("RBK-")

    # 2. Host isolation (en0)
    iso = next(act for act in actions if act.action_type == "ISOLATE_HOST")
    assert "ifconfig en0 down" in iso.command_snippet
    assert "ifconfig en0 up" in iso.rollback_snippet


def test_atomic_rollback_generation_and_export(mock_incident):
    """
    Tests atomic reverse rollback script generation for both bash and PowerShell.
    """
    engine = PlaybookEngine()

    # Linux rollback script
    actions_linux = engine.generate_mitigations(mock_incident, platform="linux")
    rbk_sh_path = "test_rollback.sh"
    content_sh = engine.export_rollback_script(actions_linux, rbk_sh_path, platform="linux")
    assert os.path.exists(rbk_sh_path)
    assert "#!/bin/bash" in content_sh
    assert "ATOMIC SOAR ROLLBACK" in content_sh
    assert "iptables -D" in content_sh
    assert "eth0 up" in content_sh
    if os.path.exists(rbk_sh_path):
        os.remove(rbk_sh_path)

    # Windows rollback script
    actions_win = engine.generate_mitigations(mock_incident, platform="windows")
    rbk_ps1_path = "test_rollback.ps1"
    content_ps1 = engine.export_rollback_script(actions_win, rbk_ps1_path, platform="windows")
    assert os.path.exists(rbk_ps1_path)
    assert "POWERSHELL" in content_ps1
    assert "Remove-NetFirewallRule" in content_ps1
    assert "Enable-NetAdapter" in content_ps1
    if os.path.exists(rbk_ps1_path):
        os.remove(rbk_ps1_path)


def test_report_generation(mock_incident):
    ti_engine = ThreatIntelEngine()
    reporter = IncidentReporter()
    playbook = PlaybookEngine()
    
    threat_data = ti_engine.lookup_ip(mock_incident.primary_actor_ip)
    actions = playbook.generate_mitigations(mock_incident, platform="linux")
    
    report_path = "TEST_INCIDENT_REPORT.md"
    report_content = reporter.generate_markdown_report(
        mock_incident, threat_data, actions, report_path
    )
    
    assert os.path.exists(report_path)
    assert "# ATTACKTRACE Forensic Incident Report" in report_content
    assert "185.220.101.5" in report_content
    assert "Germany" in report_content
    assert "T1048" in report_content
    
    # Clean up
    if os.path.exists(report_path):
        os.remove(report_path)


def test_soar_db_persistence_with_tokens(mock_incident):
    """
    Verifies that generated SOAR actions with rollback tokens are properly saved
    and retrieved from the SQLite database.
    """
    from src.db import DatabaseManager

    db = DatabaseManager(":memory:")
    engine = PlaybookEngine()

    # Save incident first
    db.save_incident(mock_incident, is_demo=False)

    # Generate and persist actions
    actions = engine.generate_mitigations(mock_incident, platform="windows")
    db.save_soar_actions(mock_incident.incident_id, actions)

    # Retrieve from DB
    retrieved = db.get_soar_actions(mock_incident.incident_id)
    assert len(retrieved) == 3

    for act in retrieved:
        assert act.rollback_token.startswith("RBK-")
        assert act.rollback_snippet != ""
        assert act.status == "SIMULATED"

    db.close()


def test_api_mitigate_and_rollback_endpoints():
    """
    Tests POST /api/v1/incidents/{incident_id}/mitigate and
    GET /api/v1/incidents/{incident_id}/rollback-script.
    """
    from fastapi.testclient import TestClient
    from src.api import app, pipeline

    client = TestClient(app)

    # Ingest logs to create an active incident
    scenario_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "attack_scenario.json"
    )
    pipeline.run_pipeline(scenario_path)
    assert len(pipeline.incidents) >= 1
    incident_id = pipeline.incidents[0].incident_id

    # 1. POST mitigate with Windows platform
    res_mitigate = client.post(f"/api/v1/incidents/{incident_id}/mitigate?platform=windows")
    assert res_mitigate.status_code == 200
    actions_data = res_mitigate.json()
    assert len(actions_data) >= 1
    for act in actions_data:
        assert act["rollback_token"].startswith("RBK-")
        assert act["rollback_snippet"] != ""

    # 2. GET rollback script
    res_rbk = client.get(f"/api/v1/incidents/{incident_id}/rollback-script?platform=windows")
    assert res_rbk.status_code == 200
    assert "POWERSHELL" in res_rbk.text
    assert "Remove-NetFirewallRule" in res_rbk.text

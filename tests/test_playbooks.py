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
    actions = engine.generate_mitigations(mock_incident)
    
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
    script_content = engine.export_mitigation_script(actions, script_path)
    assert os.path.exists(script_path)
    assert "#!/bin/bash" in script_content
    assert "iptables" in script_content
    assert "ROLLBACK PROCEDURES" in script_content
    
    # Clean up
    if os.path.exists(script_path):
        os.remove(script_path)


def test_report_generation(mock_incident):
    ti_engine = ThreatIntelEngine()
    reporter = IncidentReporter()
    playbook = PlaybookEngine()
    
    threat_data = ti_engine.lookup_ip(mock_incident.primary_actor_ip)
    actions = playbook.generate_mitigations(mock_incident)
    
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

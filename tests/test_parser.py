import os
import pytest
from src.models import UnifiedEvent, SeverityLevel, EnrichedSecurityEvent
from src.mitre_mapper import MitreMapper
from src.parser import SecurityParser, INDICATOR_WEIGHTS
from src.pipeline import AttackTracePipeline


def create_base_event(
    resource=None,
    raw_payload=None,
    status=200,
    event_type="API_REQUEST",
    source_type="web",
    user=None,
) -> UnifiedEvent:
    return UnifiedEvent(
        timestamp="2026-08-23T12:00:00Z",
        source_type=source_type,
        event_type=event_type,
        user=user,
        source_ip="192.168.1.100",
        resource=resource,
        status=status,
        raw_payload=raw_payload or {},
    )


def test_sqli_signature():
    """
    Checks that SQL Injection patterns are detected and mapped to T1190.
    """
    event = create_base_event(resource="SELECT * FROM users WHERE username = 'admin' UNION SELECT * FROM credentials")
    tactics, techniques, indicators = MitreMapper.map_event(event)

    assert "SQL_INJECTION_PATTERN" in indicators
    assert "Initial Access" in tactics
    assert any(tech["id"] == "T1190" for tech in techniques)


def test_brute_force_signature():
    """
    Checks brute force is detected on 401/403 status or LOGIN_FAILED event type.
    """
    event_failed = create_base_event(event_type="LOGIN_FAILED", status=401)
    tactics, techniques, indicators = MitreMapper.map_event(event_failed)

    assert "AUTH_FAILURE" in indicators or "FAILED_AUTH_BURST" in indicators
    assert "Credential Access" in tactics
    assert any(tech["id"] == "T1110" for tech in techniques)


def test_privilege_escalation_signature():
    """
    Checks privilege escalation is detected on sudo or root commands.
    """
    event = create_base_event(resource="sudo chmod 777 /etc/sudoers", user="admin")
    tactics, techniques, indicators = MitreMapper.map_event(event)

    assert "PRIVILEGE_ESCALATION" in indicators
    assert "Privilege Escalation" in tactics
    assert "Defense Evasion" in tactics
    assert any(tech["id"] == "T1078" for tech in techniques)
    assert any(tech["id"] == "T1548" for tech in techniques)


def test_unauthorized_exfiltration_signature():
    """
    Checks exfiltration indicators.
    """
    event = create_base_event(resource="/api/v1/data/export", raw_payload={"rows_returned": 50})
    tactics, techniques, indicators = MitreMapper.map_event(event)

    assert "UNAUTHORIZED_EXFILTRATION" in indicators
    assert "Collection" in tactics
    assert "Exfiltration" in tactics
    assert any(tech["id"] == "T1005" for tech in techniques)
    assert any(tech["id"] == "T1048" for tech in techniques)


def test_suspicious_web_recon_signature():
    """
    Checks web scanning endpoints trigger active scanning recon alerts.
    """
    event = create_base_event(resource="/.env")
    tactics, techniques, indicators = MitreMapper.map_event(event)

    assert "SUSPICIOUS_WEB_RECON" in indicators
    assert "Reconnaissance" in tactics
    assert any(tech["id"] == "T1595" for tech in techniques)


def test_risk_score_and_severity_calculation():
    """
    Verifies that the risk score sums correctly and falls into correct brackets.
    """
    parser = SecurityParser()

    # 1. Benign Event (No indicators)
    event_benign = create_base_event(resource="/index.html")
    enriched_benign = parser.parse(event_benign)
    assert enriched_benign.risk_score == 0
    assert enriched_benign.severity == SeverityLevel.INFO

    # 2. Single Low Risk (Recon)
    event_recon = create_base_event(resource="/.env")
    enriched_recon = parser.parse(event_recon)
    assert enriched_recon.risk_score == INDICATOR_WEIGHTS["SUSPICIOUS_WEB_RECON"]  # 25
    assert enriched_recon.severity == SeverityLevel.LOW

    # 3. High Risk (SQLi)
    event_sqli = create_base_event(resource="UNION SELECT")
    enriched_sqli = parser.parse(event_sqli)
    assert enriched_sqli.risk_score == INDICATOR_WEIGHTS["SQL_INJECTION_PATTERN"]  # 75
    assert enriched_sqli.severity == SeverityLevel.HIGH

    # 4. Critical Risk (SQLi + Exfiltration combo capped at 100)
    event_combo = create_base_event(resource="UNION SELECT /export", raw_payload={"rows_returned": 20})
    enriched_combo = parser.parse(event_combo)
    # Weight: 75 (SQLi) + 80 (Exfil) = 155 -> capped at 100
    assert enriched_combo.risk_score == 100
    assert enriched_combo.severity == SeverityLevel.CRITICAL


def test_attacktrace_pipeline_flow():
    """
    Runs the pipeline against the attack_scenario.json file.
    """
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")
    
    pipeline = AttackTracePipeline()
    enriched_events = pipeline.run_batch(scenario_path)

    # Ingested 9 events, 0 dropped in scenario
    assert len(enriched_events) == 9
    assert len(pipeline.collector.valid_events) == 9
    assert len(pipeline.collector.dropped_events) == 0

    # Let's check some sequential steps
    # Event 0: Recon
    assert "SUSPICIOUS_WEB_RECON" in enriched_events[0].indicators
    assert enriched_events[0].severity == SeverityLevel.LOW

    # Event 1 & 2: Failed logins
    assert "AUTH_FAILURE" in enriched_events[1].indicators or "FAILED_AUTH_BURST" in enriched_events[1].indicators
    assert "FAILED_AUTH_BURST" in enriched_events[2].indicators
    
    # Event 4: SQL Injection
    assert "SQL_INJECTION_PATTERN" in enriched_events[4].indicators

    # Event 5: Privilege Escalation
    assert "PRIVILEGE_ESCALATION" in enriched_events[5].indicators
    assert enriched_events[5].severity == SeverityLevel.HIGH

    # Event 7 & 8: Benign
    assert enriched_events[7].severity == SeverityLevel.INFO
    assert enriched_events[8].severity == SeverityLevel.INFO

import os
import pytest
from src.models import UnifiedEvent, SeverityLevel, EnrichedSecurityEvent, KillChainStage
from src.correlation import ThreatCorrelator, map_tactic_to_stage
from src.timeline import AttackTimelineRenderer
from src.parser import SecurityParser
from src.pipeline import AttackTracePipeline


def create_enriched_event(
    timestamp: str,
    source_ip: str,
    user: str,
    resource: str,
    status: int,
    event_type: str = "API_REQUEST",
    source_type: str = "web",
) -> EnrichedSecurityEvent:
    base = UnifiedEvent(
        timestamp=timestamp,
        source_type=source_type,
        event_type=event_type,
        user=user,
        source_ip=source_ip,
        resource=resource,
        status=status,
        raw_payload={},
    )
    # Parse to enrich
    parser = SecurityParser()
    return parser.parse(base)


def test_tactic_to_stage_mapping():
    """
    Validates correct translation from MITRE tactics to KillChainStage.
    """
    assert map_tactic_to_stage("Reconnaissance") == KillChainStage.RECONNAISSANCE
    assert map_tactic_to_stage("Initial Access") == KillChainStage.INITIAL_ACCESS
    assert map_tactic_to_stage("Credential Access") == KillChainStage.CREDENTIAL_ACCESS
    assert map_tactic_to_stage("Execution") == KillChainStage.EXECUTION
    assert map_tactic_to_stage("Privilege Escalation") == KillChainStage.PRIVILEGE_ESCALATION
    assert map_tactic_to_stage("Defense Evasion") == KillChainStage.PRIVILEGE_ESCALATION
    assert map_tactic_to_stage("Collection") == KillChainStage.EXFILTRATION
    assert map_tactic_to_stage("Exfiltration") == KillChainStage.EXFILTRATION
    assert map_tactic_to_stage("Impact") == KillChainStage.UNKNOWN


def test_actor_grouping_and_windowing():
    """
    Checks that events within the time window and matching IP/user criteria are clustered.
    """
    correlator = ThreatCorrelator()

    events = [
        # Web recon from IP A
        create_enriched_event("2026-08-23T12:00:00Z", "198.51.100.10", None, "/.env", 404),
        # Login fail from IP A (links via IP)
        create_enriched_event("2026-08-23T12:15:00Z", "198.51.100.10", "admin", "/login", 401, "LOGIN_FAILED", "auth"),
        # Command execution from 127.0.0.1 by user admin (links via user admin)
        create_enriched_event("2026-08-23T12:30:00Z", "127.0.0.1", "admin", "sudo chmod 777", 0, "COMMAND_EXECUTION", "system"),
        # Separate scan from IP B (different actor)
        create_enriched_event("2026-08-23T12:05:00Z", "198.51.100.20", None, "/.env", 404),
        # Out-of-window event from IP A (90 mins later)
        create_enriched_event("2026-08-23T14:00:00Z", "198.51.100.10", "guest", "/login", 401, "LOGIN_FAILED", "auth"),

    ]

    incidents = correlator.correlate(events, time_window_minutes=60)

    # 1. IP A group should contain the first 3 events (Recon -> Brute Force -> Privilege Escalation).
    #    It has 3 stages (RECONNAISSANCE, CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION) -> promoted.
    # 2. IP B has only 1 scan event, risk 25 (under threshold stage count < 2 and risk <= 60) -> discarded.
    # 3. The out-of-window IP A login failure is isolated and only 1 stage/low risk -> discarded.
    
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.primary_actor_ip == "198.51.100.10"
    assert "admin" in inc.targeted_users
    assert len(inc.steps) == 3
    assert inc.overall_severity == SeverityLevel.HIGH  # Privilege escalation risk is 85
    assert inc.confidence_score > 70


def test_incident_filtering():
    """
    Checks that isolated low-severity events are filtered out while high risk is retained.
    """
    correlator = ThreatCorrelator()

    # Case 1: Isolated scan (Low severity, 1 stage) -> discarded
    low_event = [create_enriched_event("2026-08-23T12:00:00Z", "198.51.100.10", None, "/.env", 404)]
    assert len(correlator.correlate(low_event)) == 0

    # Case 2: Isolated SQL Injection (High severity, risk score 75 > 60) -> promoted
    high_event = [create_enriched_event("2026-08-23T12:00:00Z", "198.51.100.10", "db_user", "UNION SELECT", 200, "QUERY_EXECUTION", "database")]
    incidents = correlator.correlate(high_event)
    assert len(incidents) == 1
    assert incidents[0].overall_severity == SeverityLevel.HIGH


def test_timeline_rendering():
    """
    Validates the story text and ASCII tree rendering format.
    """
    correlator = ThreatCorrelator()
    renderer = AttackTimelineRenderer()

    events = [
        create_enriched_event("2026-08-23T12:00:00Z", "198.51.100.10", None, "/.env", 404),
        create_enriched_event("2026-08-23T12:15:00Z", "198.51.100.10", "admin", "/login", 401, "LOGIN_FAILED", "auth"),
    ]

    incidents = correlator.correlate(events)
    assert len(incidents) == 1
    inc = incidents[0]

    story = renderer.generate_story(inc)
    assert "198.51.100.10" in story
    assert "admin" in story
    assert "RECONNAISSANCE" in story

    ascii_graph = renderer.render_ascii_graph(inc)
    assert "ATTACK GRAPH" in ascii_graph
    assert "198.51.100.10" in ascii_graph
    assert "T1595" in ascii_graph
    assert "T1110" in ascii_graph


def test_pipeline_integration_runs():
    """
    Verifies that the entire 3-layer pipeline processes the attack scenario successfully.
    """
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")

    pipeline = AttackTracePipeline()
    incidents = pipeline.run_pipeline(scenario_path)

    # In attack_scenario.json, the multi-stage attack from 185.220.101.5 represents:
    # Recon -> Failed Logins -> Success Login -> SQLi -> Privilege Escalation -> Exfiltration
    # This forms a single massive AttackIncident
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.primary_actor_ip == "185.220.101.5"
    assert "admin" in inc.targeted_users
    assert inc.overall_severity == SeverityLevel.CRITICAL  # SQLi + Exfil exceeds 100 capped risk
    assert inc.confidence_score >= 90
    assert len(inc.stages_detected) >= 4

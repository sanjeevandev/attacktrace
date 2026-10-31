import pytest
from src.models import UnifiedEvent, SeverityLevel, EnrichedSecurityEvent
from src.mitre_mapper import MitreMapper
from src.parser import SecurityParser
from src.correlation import ThreatCorrelator


def create_event(
    timestamp: str = "2026-08-23T12:00:00Z",
    source_ip: str = "198.51.100.10",
    user: str = "app_user",
    resource: str = "/status",
    status: int = 200,
    event_type: str = "API_REQUEST",
    source_type: str = "web",
    raw_payload: dict = None,
) -> UnifiedEvent:
    return UnifiedEvent(
        timestamp=timestamp,
        source_type=source_type,
        event_type=event_type,
        user=user,
        source_ip=source_ip,
        resource=resource,
        status=status,
        raw_payload=raw_payload or {},
    )


def test_sqli_no_false_positive_on_cli_flags():
    """
    Test false-positive prevention: CLI flags like --verbose, --config must NOT trigger SQLi.
    Real SQL injection patterns with comments '-- ' or SQL keywords must trigger SQLi.
    """
    # 1. Benign CLI flags
    event_verbose = create_event(
        resource="python3 run_diagnostics.py --verbose",
        raw_payload={"command": "systemctl restart worker --config /etc/worker.conf"}
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_verbose)
    assert "SQL_INJECTION_PATTERN" not in indicators
    assert "Initial Access" not in tactics
    assert not any(t["id"] == "T1190" for t in techniques)

    # 2. Legitimate SQLi with comment syntax '-- '
    event_sqli_comment = create_event(
        resource="SELECT * FROM accounts WHERE id = 1; -- suppress remaining query"
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_sqli_comment)
    assert "SQL_INJECTION_PATTERN" in indicators
    assert any(t["id"] == "T1190" for t in techniques)

    # 3. Classic SQLi tautology
    event_sqli_tautology = create_event(
        resource="/search?q=' OR '1'='1"
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_sqli_tautology)
    assert "SQL_INJECTION_PATTERN" in indicators


def test_single_failed_login_vs_burst():
    """
    Test single failed login flags AUTH_FAILURE with low risk,
    while multiple attempts or bursts flag FAILED_AUTH_BURST.
    """
    parser = SecurityParser()

    # 1. Single failed login (attempt: 1, 401)
    event_single = create_event(
        event_type="LOGIN_FAILED",
        status=401,
        user="bob",
        raw_payload={"attempt": 1}
    )
    enriched_single = parser.parse(event_single)
    assert "AUTH_FAILURE" in enriched_single.indicators
    assert "FAILED_AUTH_BURST" not in enriched_single.indicators
    assert enriched_single.risk_score == 15
    assert enriched_single.severity in [SeverityLevel.INFO, SeverityLevel.LOW]

    # 2. Multiple failed attempts (attempt: 5)
    event_burst = create_event(
        event_type="LOGIN_FAILED",
        status=401,
        user="bob",
        raw_payload={"attempt": 5}
    )
    enriched_burst = parser.parse(event_burst)
    assert "FAILED_AUTH_BURST" in enriched_burst.indicators
    assert enriched_burst.risk_score >= 35


def test_routine_root_user_no_privilege_escalation():
    """
    Test routine root user event without elevation command does NOT flag PRIVILEGE_ESCALATION.
    Explicit elevation commands (sudo, chmod 777, etc.) must still flag PRIVILEGE_ESCALATION.
    """
    # 1. Benign root action
    event_root_benign = create_event(
        user="root",
        source_type="system",
        event_type="PROCESS_START",
        resource="/usr/bin/python3 /opt/cron/cleanup.py"
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_root_benign)
    assert "PRIVILEGE_ESCALATION" not in indicators
    assert "Privilege Escalation" not in tactics
    assert not any(t["id"] in ["T1078", "T1548"] for t in techniques)

    # 2. Action with elevation command
    event_root_elevation = create_event(
        user="admin",
        source_type="system",
        event_type="COMMAND_EXECUTION",
        resource="sudo chmod 777 /etc/sudoers"
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_root_elevation)
    assert "PRIVILEGE_ESCALATION" in indicators
    assert any(t["id"] == "T1548" for t in techniques)


def test_bounded_sliding_window_splits_long_campaign():
    """
    Test that events with inter-event gaps <= 60 minutes spanning > 4 hours (240 minutes)
    are split into 2 separate incidents due to the maximum campaign duration ceiling.
    """
    correlator = ThreatCorrelator()
    parser = SecurityParser()

    # Create 6 events for actor IP 198.51.100.99
    # Each spaced 50 minutes apart:
    # 0m, 50m, 100m, 150m, 200m -> All <= 240m (Group 1)
    # 250m -> 50m from previous, but 250m > 240m from root! -> Must start Group 2
    # 300m -> 50m from event at 250m -> (Group 2)
    timestamps = [
        "2026-08-23T10:00:00Z",  # 0m: Recon + SQLi (Stages: Recon, Initial Access -> Risk: 100)
        "2026-08-23T10:50:00Z",  # 50m: Sudo elevation (Stage: PrivEsc)
        "2026-08-23T11:40:00Z",  # 100m: Sudo elevation
        "2026-08-23T12:30:00Z",  # 150m: Exfiltration (Stage: Exfil)
        "2026-08-23T13:20:00Z",  # 200m: Exfiltration
        "2026-08-23T14:10:00Z",  # 250m: New slice - SQLi (Risk: 75)
        "2026-08-23T15:00:00Z",  # 300m: PrivEsc (Risk: 85)
    ]

    resources = [
        "UNION SELECT * FROM credentials",
        "sudo chmod +s /bin/bash",
        "sudo chmod 777 /etc/shadow",
        "/api/v1/data/export",
        "select * from credentials",
        "UNION SELECT * FROM users",
        "sudo su -",
    ]

    enriched_events = []
    for ts, res in zip(timestamps, resources):
        raw = create_event(
            timestamp=ts,
            source_ip="198.51.100.99",
            user="attacker",
            resource=res,
        )
        enriched_events.append(parser.parse(raw))

    incidents = correlator.correlate(
        enriched_events,
        time_window_minutes=60,
        max_campaign_duration_minutes=240,
    )

    # Without max_campaign_duration_minutes, all 7 would daisy-chain into 1 incident.
    # With dual-bounding (240 min limit), events at 250m and 300m form a separate incident.
    assert len(incidents) == 2, f"Expected 2 split incidents, but got {len(incidents)}"
    
    # First incident contains the first 5 events (0m to 200m)
    assert len(incidents[0].steps) == 5
    # Second incident contains the remaining 2 events (250m to 300m)
    assert len(incidents[1].steps) == 2


def test_exfiltration_threshold_calibration():
    """
    Test that legitimate queries returning 50 rows do not trigger exfiltration,
    while large bulk queries (>= 1000 rows) or sensitive targets trigger exfiltration.
    """
    # 1. Benign query returning 50 rows from ordinary table
    event_benign_query = create_event(
        resource="SELECT id, product_name, price FROM catalog_products",
        raw_payload={"rows_returned": 50, "response_time_ms": 600}
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_benign_query)
    assert "UNAUTHORIZED_EXFILTRATION" not in indicators

    # 2. Bulk query with >= 1000 rows
    event_bulk = create_event(
        resource="SELECT * FROM transactions",
        raw_payload={"rows_returned": 1500}
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_bulk)
    assert "UNAUTHORIZED_EXFILTRATION" in indicators

    # 3. Sensitive target
    event_sensitive = create_event(
        resource="/api/v1/auth/tokens"
    )
    tactics, techniques, indicators = MitreMapper.map_event(event_sensitive)
    assert "UNAUTHORIZED_EXFILTRATION" in indicators

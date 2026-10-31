import os
import tempfile
import uuid
import pytest
from pathlib import Path

from src.db import DatabaseManager
from src.models import (
    AttackIncident,
    AttackStep,
    EnrichedSecurityEvent,
    KillChainStage,
    MitigationAction,
    SeverityLevel,
    ThreatIntelData,
    UnifiedEvent,
)
from src.pipeline import AttackTracePipeline


@pytest.fixture
def temp_db():
    """Provides a fresh temporary SQLite database file for isolation."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_path = tf.name
    db = DatabaseManager(db_path=temp_path)
    yield db
    db.close()
    if os.path.exists(temp_path):
        os.remove(temp_path)


@pytest.fixture
def memory_db():
    """Provides an in-memory SQLite database."""
    db = DatabaseManager(db_path=":memory:")
    yield db
    db.close()


def test_db_initialization(temp_db):
    """Verifies tables and schema migration table are initialized."""
    with temp_db.connection() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        assert "events" in tables
        assert "enriched_events" in tables
        assert "incidents" in tables
        assert "attack_steps" in tables
        assert "soar_actions" in tables
        assert "schema_migrations" in tables

        # Verify migration record
        mig_cur = conn.execute("SELECT version FROM schema_migrations WHERE version = 1;")
        assert mig_cur.fetchone() is not None


def test_save_and_retrieve_events(temp_db):
    """Verifies saving and querying unified events."""
    event1 = UnifiedEvent(
        event_id="evt-100",
        timestamp="2026-10-31T20:00:00Z",
        source_type="web",
        event_type="LOGIN_FAILED",
        user="admin",
        source_ip="198.51.100.1",
        resource="/login",
        status=401,
        raw_payload={"attempt": 1},
    )
    event2 = UnifiedEvent(
        event_id="evt-101",
        timestamp="2026-10-31T20:01:00Z",
        source_type="db",
        event_type="SQL_QUERY",
        user="db_user",
        source_ip="198.51.100.1",
        resource="credentials",
        status=200,
        raw_payload={"query": "SELECT *"},
    )
    temp_db.save_events([event1, event2], is_demo=False)

    stats = temp_db.get_stats()
    assert stats["total_ingested"] == 2


def test_save_and_retrieve_enriched_events(temp_db):
    """Verifies enriched events persist with tactics, techniques, and risk scores."""
    base_evt = UnifiedEvent(
        event_id="evt-200",
        timestamp="2026-10-31T20:05:00Z",
        source_type="api",
        event_type="API_CALL",
        source_ip="203.0.113.5",
        raw_payload={},
    )
    enriched = EnrichedSecurityEvent(
        base_event=base_evt,
        severity=SeverityLevel.HIGH,
        mitre_tactics=["Initial Access"],
        mitre_techniques=[{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        indicators=["SQL_INJECTION_PATTERN"],
        risk_score=75,
    )
    temp_db.save_enriched_events([enriched], is_demo=False)

    stats = temp_db.get_stats()
    assert stats["total_ingested"] == 1
    assert stats["max_risk"] == 75


def test_incident_persistence_with_hooks(temp_db):
    """Verifies parent_step_id and rollback_token hooks persist and deserialize."""
    step1_id = str(uuid.uuid4())
    step2_id = str(uuid.uuid4())

    step1 = AttackStep(
        step_id=step1_id,
        stage=KillChainStage.RECONNAISSANCE,
        timestamp="2026-10-31T20:10:00Z",
        technique="T1595 - Active Scanning",
        description="Scanning web root",
        actor="185.220.101.5",
        risk_score=25,
        step_index=0,
        parent_step_id=None,
    )
    step2 = AttackStep(
        step_id=step2_id,
        stage=KillChainStage.INITIAL_ACCESS,
        timestamp="2026-10-31T20:12:00Z",
        technique="T1190 - Exploit Public-Facing Application",
        description="SQL injection attempted",
        actor="185.220.101.5",
        risk_score=85,
        step_index=1,
        parent_step_id=step1_id,
    )

    threat_intel = ThreatIntelData(
        ip="185.220.101.5",
        reputation_score=95,
        threat_actor_category="Tor Exit Node",
        country="Germany",
        is_tor_exit_node=True,
    )

    incident_id = "inc-real-001"
    incident = AttackIncident(
        incident_id=incident_id,
        primary_actor_ip="185.220.101.5",
        targeted_users=["admin"],
        start_time="2026-10-31T20:10:00Z",
        end_time="2026-10-31T20:12:00Z",
        overall_severity=SeverityLevel.HIGH,
        confidence_score=90,
        stages_detected=[KillChainStage.RECONNAISSANCE, KillChainStage.INITIAL_ACCESS],
        steps=[step1, step2],
        threat_intel=threat_intel,
    )

    action = MitigationAction(
        action_type="FIREWALL_BLOCK",
        target="185.220.101.5",
        command_snippet="sudo iptables -A INPUT -s 185.220.101.5 -j DROP",
        rollback_snippet="sudo iptables -D INPUT -s 185.220.101.5 -j DROP",
        status="SIMULATED",
    )

    # Save incident and action
    temp_db.save_incident(incident, is_demo=False, actions=[action])

    # Fetch incident back
    retrieved = temp_db.get_incident_by_id(incident_id)
    assert retrieved is not None
    assert retrieved.incident_id == incident_id
    assert retrieved.primary_actor_ip == "185.220.101.5"
    assert retrieved.overall_severity == SeverityLevel.HIGH
    assert len(retrieved.steps) == 2
    assert retrieved.steps[0].step_id == step1_id
    assert retrieved.steps[0].parent_step_id is None
    assert retrieved.steps[1].step_id == step2_id
    assert retrieved.steps[1].parent_step_id == step1_id  # Hook verified!

    # Fetch actions back
    retrieved_actions = temp_db.get_soar_actions(incident_id)
    assert len(retrieved_actions) == 1
    assert retrieved_actions[0].action_type == "FIREWALL_BLOCK"
    assert retrieved_actions[0].rollback_snippet == "sudo iptables -D INPUT -s 185.220.101.5 -j DROP"
    assert retrieved_actions[0].rollback_token is not None  # Token hook verified!


def test_clear_demo_data_isolation(temp_db):
    """Verifies that clear_demo_data purges only demo records, preserving real records."""
    real_inc = AttackIncident(
        incident_id="inc-real-999",
        primary_actor_ip="198.51.100.50",
        targeted_users=["analyst"],
        start_time="2026-10-31T18:00:00Z",
        end_time="2026-10-31T18:10:00Z",
        overall_severity=SeverityLevel.LOW,
        confidence_score=60,
        stages_detected=[KillChainStage.RECONNAISSANCE],
        steps=[],
    )
    demo_inc = AttackIncident(
        incident_id="inc-demo-111",
        primary_actor_ip="203.0.113.99",
        targeted_users=["demo_user"],
        start_time="2026-10-31T19:00:00Z",
        end_time="2026-10-31T19:15:00Z",
        overall_severity=SeverityLevel.CRITICAL,
        confidence_score=95,
        stages_detected=[KillChainStage.INITIAL_ACCESS],
        steps=[],
    )

    temp_db.save_incident(real_inc, is_demo=False)
    temp_db.save_incident(demo_inc, is_demo=True)

    # Pre-clear checks
    all_incidents = temp_db.get_incidents(limit=10)
    assert len(all_incidents) == 2

    # Clear demo data
    res = temp_db.clear_demo_data()
    assert res["incidents_deleted"] == 1

    # Post-clear checks
    remaining = temp_db.get_incidents(limit=10)
    assert len(remaining) == 1
    assert remaining[0].incident_id == "inc-real-999"
    assert temp_db.get_incident_by_id("inc-demo-111") is None


def test_cascade_delete_on_incident(temp_db):
    """Verifies foreign key CASCADE deletes child steps and SOAR actions."""
    inc_id = "inc-cascade-test"
    step = AttackStep(
        step_id="step-cas-1",
        stage=KillChainStage.EXECUTION,
        timestamp="2026-10-31T20:20:00Z",
        technique="T1059",
        description="Command execution",
        actor="10.0.0.1",
        risk_score=50,
    )
    inc = AttackIncident(
        incident_id=inc_id,
        primary_actor_ip="10.0.0.1",
        targeted_users=["root"],
        start_time="2026-10-31T20:20:00Z",
        end_time="2026-10-31T20:20:00Z",
        overall_severity=SeverityLevel.MEDIUM,
        confidence_score=50,
        stages_detected=[KillChainStage.EXECUTION],
        steps=[step],
    )
    action = MitigationAction(
        action_type="ISOLATE_HOST",
        target="compromised_host",
        command_snippet="ip link set dev eth0 down",
        rollback_snippet="ip link set dev eth0 up",
    )
    temp_db.save_incident(inc, actions=[action])

    # Ensure steps and actions exist
    assert len(temp_db.get_soar_actions(inc_id)) == 1

    # Delete the parent incident directly
    with temp_db.connection() as conn:
        conn.execute("DELETE FROM incidents WHERE incident_id = ?;", (inc_id,))
        conn.commit()

        # Check that steps and actions were cascade deleted
        s_cur = conn.execute("SELECT COUNT(*) AS cnt FROM attack_steps WHERE incident_id = ?;", (inc_id,))
        assert s_cur.fetchone()["cnt"] == 0

        a_cur = conn.execute("SELECT COUNT(*) AS cnt FROM soar_actions WHERE incident_id = ?;", (inc_id,))
        assert a_cur.fetchone()["cnt"] == 0


def test_pipeline_integration_with_db(memory_db):
    """Verifies AttackTracePipeline automatically persists events and incidents into DatabaseManager."""
    project_dir = Path(__file__).resolve().parent.parent
    scenario_path = str(project_dir / "data" / "attack_scenario.json")

    pipeline = AttackTracePipeline(db=memory_db)
    incidents = pipeline.run_pipeline(scenario_path, time_window_minutes=60, is_demo=False)

    assert len(incidents) >= 1

    # Query DB to ensure pipeline persisted everything
    db_incidents = memory_db.get_incidents()
    assert len(db_incidents) == len(incidents)
    assert db_incidents[0].primary_actor_ip == "185.220.101.5"

    stats = memory_db.get_stats()
    assert stats["total_ingested"] == 9
    assert stats["total_incidents"] >= 1

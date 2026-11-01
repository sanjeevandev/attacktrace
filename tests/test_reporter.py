import json
import os
import pytest

from src.models import (
    AttackIncident,
    AttackStep,
    KillChainStage,
    MitigationAction,
    SeverityLevel,
    ThreatIntelData,
)
from src.reporter import IncidentReporter
from src.threat_intel import ThreatIntelEngine
from src.playbooks import PlaybookEngine


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def mock_incident():
    """Construct a CRITICAL severity incident with causal step linkage."""
    step1 = AttackStep(
        stage=KillChainStage.RECONNAISSANCE,
        timestamp="2026-08-23T17:40:00Z",
        technique="T1595 - Active Scanning",
        description="Port scanning detected from external IP",
        actor="185.220.101.5",
        risk_score=25,
        step_index=1,
        step_id="step-001",
        parent_step_id=None,
    )
    step2 = AttackStep(
        stage=KillChainStage.INITIAL_ACCESS,
        timestamp="2026-08-23T17:41:00Z",
        technique="T1190 - Exploit Public-Facing Application",
        description="SQL injection against web portal",
        actor="185.220.101.5",
        risk_score=60,
        step_index=2,
        step_id="step-002",
        parent_step_id="step-001",
    )
    step3 = AttackStep(
        stage=KillChainStage.PRIVILEGE_ESCALATION,
        timestamp="2026-08-23T17:42:00Z",
        technique="T1068 - Exploitation for Privilege Escalation",
        description="Kernel exploit used to elevate to root",
        actor="185.220.101.5",
        risk_score=85,
        step_index=3,
        step_id="step-003",
        parent_step_id="step-002",
    )
    step4 = AttackStep(
        stage=KillChainStage.EXFILTRATION,
        timestamp="2026-08-23T17:44:00Z",
        technique="T1048 - Exfiltration Over Alternative Protocol",
        description="Exfiltrated database tables via DNS tunneling",
        actor="185.220.101.5",
        risk_score=95,
        step_index=4,
        step_id="step-004",
        parent_step_id="step-003",
    )
    return AttackIncident(
        incident_id="INC-TEST-0001",
        primary_actor_ip="185.220.101.5",
        targeted_users=["admin", "db_service"],
        start_time="2026-08-23T17:40:00Z",
        end_time="2026-08-23T17:44:00Z",
        overall_severity=SeverityLevel.CRITICAL,
        confidence_score=90,
        stages_detected=[
            KillChainStage.RECONNAISSANCE,
            KillChainStage.INITIAL_ACCESS,
            KillChainStage.PRIVILEGE_ESCALATION,
            KillChainStage.EXFILTRATION,
        ],
        steps=[step1, step2, step3, step4],
    )


@pytest.fixture
def mock_threat_data():
    return ThreatIntelData(
        ip="185.220.101.5",
        reputation_score=95,
        threat_actor_category="Tor Exit Node",
        country="Germany",
        is_tor_exit_node=True,
    )


@pytest.fixture
def mock_actions():
    return [
        MitigationAction(
            action_type="FIREWALL_BLOCK",
            target="185.220.101.5",
            command_snippet="sudo iptables -A INPUT -s 185.220.101.5 -j DROP",
            rollback_snippet="sudo iptables -D INPUT -s 185.220.101.5 -j DROP",
            rollback_token="RBK-ABCD1234",
            status="SIMULATED",
            action_id="ACT-001",
        ),
        MitigationAction(
            action_type="SESSION_REVOKE",
            target="admin",
            command_snippet='sudo pkill -u admin || true',
            rollback_snippet='echo "Account credential reset required for: admin"',
            rollback_token="RBK-EFGH5678",
            status="SIMULATED",
            action_id="ACT-002",
        ),
        MitigationAction(
            action_type="ISOLATE_HOST",
            target="compromised_host",
            command_snippet="sudo ip link set dev eth0 down",
            rollback_snippet="sudo ip link set dev eth0 up",
            rollback_token="RBK-IJKL9012",
            status="SIMULATED",
            action_id="ACT-003",
        ),
    ]


@pytest.fixture
def reporter():
    return IncidentReporter()


# ------------------------------------------------------------------ #
# Tests — Markdown Report
# ------------------------------------------------------------------ #


class TestMarkdownReport:
    """Tests for generate_markdown_report()."""

    def test_report_contains_executive_summary(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "# ATTACKTRACE Forensic Incident Report" in content
        assert "## 1. Executive Summary" in content
        assert "INC-TEST-0001" in content

    def test_report_contains_duration_and_blast_radius(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "duration:" in content.lower() or "4m" in content
        assert "Blast Radius" in content
        assert "2 user(s)" in content
        assert "4 kill-chain stage(s)" in content
        assert "4 attack step(s)" in content

    def test_report_severity_badge(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "SEVERITY-CRITICAL-red" in content

    def test_report_threat_intel_section(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "## 2. Threat Intelligence & Attribution" in content
        assert "185.220.101.5" in content
        assert "95/100" in content
        assert "Tor Exit Node" in content
        assert "Germany" in content
        assert "YES" in content

    def test_report_kill_chain_section_with_causality(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "## 3. Chronological Kill-Chain Audit Trail" in content
        assert "T1595" in content
        assert "T1190" in content
        assert "T1068" in content
        assert "T1048" in content
        # Causality column — parent step references
        assert "step-001" in content
        assert "step-002" in content
        assert "step-003" in content
        # First step has no parent — should show "—"
        assert "—" in content

    def test_report_soar_section_with_rollback_tokens(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "## 4. Atomic SOAR Containment & Rollback Plan" in content
        assert "RBK-ABCD1234" in content
        assert "RBK-EFGH5678" in content
        assert "RBK-IJKL9012" in content
        assert "FIREWALL_BLOCK" in content
        assert "SESSION_REVOKE" in content
        assert "ISOLATE_HOST" in content

    def test_report_rollback_guidelines(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "### Rollback Procedure Guidelines" in content
        assert "FIREWALL_BLOCK" in content
        assert "ISOLATE_HOST" in content
        assert "SESSION_REVOKE" in content

    def test_report_file_export(
        self, reporter, mock_incident, mock_threat_data, mock_actions, tmp_path
    ):
        output_file = str(tmp_path / "test_report.md")
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, mock_actions, output_file
        )
        assert os.path.exists(output_file)
        with open(output_file, "r", encoding="utf-8") as f:
            disk_content = f.read()
        assert disk_content == content

    def test_report_empty_actions(
        self, reporter, mock_incident, mock_threat_data
    ):
        content = reporter.generate_markdown_report(
            mock_incident, mock_threat_data, []
        )
        assert "## 4. Atomic SOAR Containment & Rollback Plan" in content
        # Table header should still be present
        assert "Mitigation Type" in content


# ------------------------------------------------------------------ #
# Tests — JSON Dossier
# ------------------------------------------------------------------ #


class TestJsonDossier:
    """Tests for generate_json_dossier()."""

    def test_dossier_structure(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        assert isinstance(dossier, dict)
        assert dossier["schema_version"] == "1.0"
        assert dossier["incident_id"] == "INC-TEST-0001"
        assert dossier["primary_actor_ip"] == "185.220.101.5"
        assert dossier["overall_severity"] == "CRITICAL"
        assert dossier["confidence_score"] == 90

    def test_dossier_targeted_users(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        assert dossier["targeted_users"] == ["admin", "db_service"]

    def test_dossier_stages_detected(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        assert "RECONNAISSANCE" in dossier["stages_detected"]
        assert "EXFILTRATION" in dossier["stages_detected"]
        assert len(dossier["stages_detected"]) == 4

    def test_dossier_kill_chain_steps(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        steps = dossier["kill_chain_steps"]
        assert len(steps) == 4
        assert steps[0]["step_id"] == "step-001"
        assert steps[1]["parent_step_id"] == "step-001"
        assert steps[3]["technique"] == "T1048 - Exfiltration Over Alternative Protocol"

    def test_dossier_threat_intel_snapshot(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        ti = dossier["threat_intel"]
        assert ti["ip"] == "185.220.101.5"
        assert ti["reputation_score"] == 95
        assert ti["is_tor_exit_node"] is True
        assert ti["country"] == "Germany"

    def test_dossier_mitigations_with_tokens(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        mitigations = dossier["mitigations"]
        assert len(mitigations) == 3
        tokens = [m["rollback_token"] for m in mitigations]
        assert "RBK-ABCD1234" in tokens
        assert "RBK-EFGH5678" in tokens
        assert "RBK-IJKL9012" in tokens

    def test_dossier_duration(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        assert dossier["duration"] == "4m 0s"

    def test_dossier_serializable(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        """Ensure the dossier is fully JSON-serializable."""
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions
        )
        serialized = json.dumps(dossier, default=str)
        assert isinstance(serialized, str)
        deserialized = json.loads(serialized)
        assert deserialized["incident_id"] == "INC-TEST-0001"

    def test_dossier_file_export(
        self, reporter, mock_incident, mock_threat_data, mock_actions, tmp_path
    ):
        output_file = str(tmp_path / "dossier.json")
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions, output_file
        )
        assert os.path.exists(output_file)
        with open(output_file, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
        assert disk_data["incident_id"] == dossier["incident_id"]
        assert disk_data["schema_version"] == "1.0"

    def test_dossier_no_file_when_path_none(
        self, reporter, mock_incident, mock_threat_data, mock_actions
    ):
        """When output_path is None, no file should be created."""
        dossier = reporter.generate_json_dossier(
            mock_incident, mock_threat_data, mock_actions, output_path=None
        )
        assert isinstance(dossier, dict)
        assert dossier["incident_id"] == "INC-TEST-0001"


# ------------------------------------------------------------------ #
# Tests — MITRE ATT&CK Navigator Layer
# ------------------------------------------------------------------ #


class TestNavigatorLayer:
    """Tests for generate_navigator_layer()."""

    def test_navigator_domain(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        assert layer["domain"] == "enterprise-attack"

    def test_navigator_name(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        assert layer["name"] == "ATTACKTRACE Incident: INC-TEST-0001"

    def test_navigator_version_schema(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        assert "versions" in layer
        assert layer["versions"]["navigator"] == "4.5"
        assert layer["versions"]["layer"] == "4.5"

    def test_navigator_technique_count(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        # 4 distinct techniques: T1595, T1190, T1068, T1048
        assert len(layer["techniques"]) == 4

    def test_navigator_technique_ids(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        tech_ids = {t["techniqueID"] for t in layer["techniques"]}
        assert "T1595" in tech_ids
        assert "T1190" in tech_ids
        assert "T1068" in tech_ids
        assert "T1048" in tech_ids

    def test_navigator_technique_scores_match_risk(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        tech_map = {t["techniqueID"]: t for t in layer["techniques"]}
        assert tech_map["T1595"]["score"] == 25
        assert tech_map["T1190"]["score"] == 60
        assert tech_map["T1068"]["score"] == 85
        assert tech_map["T1048"]["score"] == 95

    def test_navigator_color_gradient(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        tech_map = {t["techniqueID"]: t for t in layer["techniques"]}
        # T1595: risk 25 → light green
        assert tech_map["T1595"]["color"] == "#66cc00"
        # T1190: risk 60 → orange
        assert tech_map["T1190"]["color"] == "#ff6600"
        # T1068: risk 85 → red
        assert tech_map["T1068"]["color"] == "#ff0000"
        # T1048: risk 95 → red
        assert tech_map["T1048"]["color"] == "#ff0000"

    def test_navigator_comments(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident)
        tech_map = {t["techniqueID"]: t for t in layer["techniques"]}
        assert "Port scanning" in tech_map["T1595"]["comment"]
        assert "DNS tunneling" in tech_map["T1048"]["comment"]

    def test_navigator_file_export(self, reporter, mock_incident, tmp_path):
        output_file = str(tmp_path / "nav_layer.json")
        layer = reporter.generate_navigator_layer(mock_incident, output_file)
        assert os.path.exists(output_file)
        with open(output_file, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
        assert disk_data["domain"] == "enterprise-attack"
        assert len(disk_data["techniques"]) == len(layer["techniques"])

    def test_navigator_no_file_when_path_none(self, reporter, mock_incident):
        layer = reporter.generate_navigator_layer(mock_incident, output_path=None)
        assert isinstance(layer, dict)
        assert layer["domain"] == "enterprise-attack"

    def test_navigator_duplicate_technique_aggregation(self, reporter):
        """When two steps share the same technique ID, the highest risk wins."""
        step_a = AttackStep(
            stage=KillChainStage.RECONNAISSANCE,
            timestamp="2026-08-23T17:40:00Z",
            technique="T1595 - Active Scanning",
            description="First scan",
            actor="10.0.0.1",
            risk_score=20,
            step_id="dup-1",
        )
        step_b = AttackStep(
            stage=KillChainStage.RECONNAISSANCE,
            timestamp="2026-08-23T17:41:00Z",
            technique="T1595 - Active Scanning",
            description="Second scan",
            actor="10.0.0.1",
            risk_score=50,
            step_id="dup-2",
        )
        inc = AttackIncident(
            incident_id="INC-DUP",
            primary_actor_ip="10.0.0.1",
            targeted_users=["user1"],
            start_time="2026-08-23T17:40:00Z",
            end_time="2026-08-23T17:41:00Z",
            overall_severity=SeverityLevel.HIGH,
            confidence_score=80,
            stages_detected=[KillChainStage.RECONNAISSANCE],
            steps=[step_a, step_b],
        )
        layer = reporter.generate_navigator_layer(inc)
        # Should be deduplicated to a single technique entry
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["score"] == 50
        assert "First scan" in layer["techniques"][0]["comment"]
        assert "Second scan" in layer["techniques"][0]["comment"]


# ------------------------------------------------------------------ #
# Tests — Helpers
# ------------------------------------------------------------------ #


class TestHelpers:
    """Tests for IncidentReporter helper methods."""

    def test_compute_duration_normal(self):
        d = IncidentReporter._compute_duration(
            "2026-08-23T17:40:00Z", "2026-08-23T17:44:00Z"
        )
        assert d == "4m 0s"

    def test_compute_duration_with_hours(self):
        d = IncidentReporter._compute_duration(
            "2026-08-23T10:00:00Z", "2026-08-23T12:30:45Z"
        )
        assert d == "2h 30m 45s"

    def test_compute_duration_invalid(self):
        d = IncidentReporter._compute_duration("not-a-date", "also-not")
        assert d == "N/A"

    def test_risk_to_navigator_color(self):
        assert IncidentReporter._risk_to_navigator_color(95) == "#ff0000"
        assert IncidentReporter._risk_to_navigator_color(65) == "#ff6600"
        assert IncidentReporter._risk_to_navigator_color(45) == "#ffcc00"
        assert IncidentReporter._risk_to_navigator_color(25) == "#66cc00"
        assert IncidentReporter._risk_to_navigator_color(5) == "#99ccff"


# ------------------------------------------------------------------ #
# Tests — API Endpoints
# ------------------------------------------------------------------ #


class TestReporterAPIEndpoints:
    """Tests for the /report, /dossier, and /navigator API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_pipeline(self):
        """Ingest scenario logs so active incidents exist for endpoint tests."""
        from src.api import pipeline, ti_engine

        scenario_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "attack_scenario.json",
        )
        if not pipeline.incidents:
            pipeline.run_pipeline(scenario_path)
            for inc in pipeline.incidents:
                ti_engine.enrich_incident(inc)

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from src.api import app

        return TestClient(app)

    @pytest.fixture
    def incident_id(self):
        from src.api import pipeline

        return pipeline.incidents[0].incident_id

    # /report endpoint

    def test_report_endpoint_success(self, client, incident_id):
        res = client.get(f"/api/v1/incidents/{incident_id}/report")
        assert res.status_code == 200
        assert "ATTACKTRACE Forensic Incident Report" in res.text
        assert "Executive Summary" in res.text

    def test_report_endpoint_not_found(self, client):
        res = client.get("/api/v1/incidents/nonexistent-id/report")
        assert res.status_code == 404

    # /dossier endpoint

    def test_dossier_endpoint_success(self, client, incident_id):
        res = client.get(f"/api/v1/incidents/{incident_id}/dossier")
        assert res.status_code == 200
        data = res.json()
        assert data["schema_version"] == "1.0"
        assert data["incident_id"] == incident_id
        assert "kill_chain_steps" in data
        assert "threat_intel" in data
        assert "mitigations" in data

    def test_dossier_endpoint_not_found(self, client):
        res = client.get("/api/v1/incidents/nonexistent-id/dossier")
        assert res.status_code == 404

    # /navigator endpoint

    def test_navigator_endpoint_success(self, client, incident_id):
        res = client.get(f"/api/v1/incidents/{incident_id}/navigator")
        assert res.status_code == 200
        data = res.json()
        assert data["domain"] == "enterprise-attack"
        assert "ATTACKTRACE Incident:" in data["name"]
        assert len(data["techniques"]) >= 1

    def test_navigator_endpoint_not_found(self, client):
        res = client.get("/api/v1/incidents/nonexistent-id/navigator")
        assert res.status_code == 404

    def test_navigator_endpoint_scores_are_integers(self, client, incident_id):
        res = client.get(f"/api/v1/incidents/{incident_id}/navigator")
        data = res.json()
        for tech in data["techniques"]:
            assert isinstance(tech["score"], int)

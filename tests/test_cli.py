import json
import os
import sys
import pytest
from unittest.mock import patch

from src.cli import main, build_parser
from src.db import DatabaseManager
from src.models import (
    AttackIncident,
    AttackStep,
    KillChainStage,
    SeverityLevel,
)


@pytest.fixture
def temp_db(tmp_path):
    """Creates a temporary SQLite database for testing CLI commands."""
    db_file = str(tmp_path / "test_cli.db")
    db = DatabaseManager(db_path=db_file)
    yield db
    db.close()


@pytest.fixture
def populated_db(temp_db):
    """Populates the temporary DB with a sample incident."""
    step = AttackStep(
        stage=KillChainStage.RECONNAISSANCE,
        timestamp="2026-08-23T17:40:00Z",
        technique="T1595 - Active Scanning",
        description="Port scanning",
        actor="185.220.101.5",
        risk_score=25,
        step_id="step-cli-1",
    )
    inc = AttackIncident(
        incident_id="INC-CLI-001",
        primary_actor_ip="185.220.101.5",
        targeted_users=["admin"],
        start_time="2026-08-23T17:40:00Z",
        end_time="2026-08-23T17:44:00Z",
        overall_severity=SeverityLevel.HIGH,
        confidence_score=85,
        stages_detected=[KillChainStage.RECONNAISSANCE],
        steps=[step],
    )
    temp_db.save_incident(inc, is_demo=False)
    return temp_db


# ---------------------------------------------------------------------- #
# 1. Version & Help Tests
# ---------------------------------------------------------------------- #


def test_cli_help(capsys):
    """Test attacktrace --help displays usage and returns code 0."""
    code = main(["--help"])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "attacktrace" in out.lower()
    assert "status" in out
    assert "demo" in out
    assert "ingest" in out
    assert "incidents" in out
    assert "report" in out
    assert "mitigate" in out


def test_cli_version(capsys):
    """Test attacktrace --version returns 0 and prints version/platform."""
    code = main(["--version"])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "ATTACKTRACE" in out
    assert "v1.0.0" in out
    assert "Platform:" in out
    assert "Python:" in out


def test_cli_no_args_shows_help(capsys):
    """Test calling attacktrace without arguments shows help and returns 0."""
    code = main([])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "ATTACKTRACE" in out


# ---------------------------------------------------------------------- #
# 2. Status Command Tests
# ---------------------------------------------------------------------- #


def test_cli_status(capsys, populated_db):
    """Test attacktrace status outputs database path, events, incidents, and severity."""
    code = main(["status", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Database Path:" in out
    assert "Total Incidents:" in out
    assert "HIGH" in out


def test_cli_status_in_memory(capsys):
    """Test attacktrace status with :memory: database."""
    mem_db = DatabaseManager(":memory:")
    code = main(["status"], db=mem_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "In-Memory" in out
    mem_db.close()


# ---------------------------------------------------------------------- #
# 3. Demo Command Tests
# ---------------------------------------------------------------------- #


def test_cli_demo_windows(capsys, temp_db):
    """Test attacktrace demo --scenario windows runs simulation and populates DB."""
    code = main(["demo", "--scenario", "windows", "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS] Scenario completed" in out
    assert "Incident ID:" in out

    # Verify incident persisted in DB
    incidents = temp_db.get_incidents()
    assert len(incidents) >= 1


def test_cli_demo_reset(capsys, temp_db):
    """Test attacktrace demo --reset purges synthetic demo data."""
    # First load a demo scenario
    main(["demo", "--scenario", "linux", "--db", temp_db.db_path], db=temp_db)
    assert len(temp_db.get_incidents(is_demo=True)) >= 1

    # Now reset
    code = main(["demo", "--reset", "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Synthetic demo state purged" in out

    # Verify zero demo incidents remain
    assert len(temp_db.get_incidents(is_demo=True)) == 0


def test_cli_demo_invalid_scenario(capsys, temp_db):
    """Test attacktrace demo with non-existent scenario returns error."""
    code = main(["demo", "--scenario", "non_existent_os", "--db", temp_db.db_path], db=temp_db)
    assert code != 0


# ---------------------------------------------------------------------- #
# 4. Ingest Command Tests
# ---------------------------------------------------------------------- #


def test_cli_ingest_json_file(capsys, temp_db):
    """Test attacktrace ingest with a valid scenario JSON file."""
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")

    code = main(["ingest", scenario_path, "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Ingested logs (L1):" in out
    assert "Correlated Incidents:" in out


def test_cli_ingest_missing_file(capsys, temp_db):
    """Test attacktrace ingest with missing file returns non-zero code."""
    code = main(["ingest", "non_existent_file.json", "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code != 0
    assert "File not found" in out


def test_cli_ingest_jsonl_file(capsys, temp_db, tmp_path):
    """Test attacktrace ingest with a JSONL (line-delimited) file."""
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scenario_path = os.path.join(project_dir, "data", "attack_scenario.json")
    with open(scenario_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    jsonl_path = str(tmp_path / "events.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    code = main(["ingest", jsonl_path, "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Ingested logs (L1):" in out


# ---------------------------------------------------------------------- #
# 5. Incidents Command Tests
# ---------------------------------------------------------------------- #


def test_cli_incidents_list(capsys, populated_db):
    """Test attacktrace incidents --list formats output table cleanly."""
    code = main(["incidents", "--list", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Correlated Attack Incidents" in out
    assert "INC-CLI-001" in out
    assert "185.220.101.5" in out


def test_cli_incidents_list_json(capsys, populated_db):
    """Test attacktrace incidents --list --json outputs valid JSON."""
    code = main(["incidents", "--list", "--json", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 0
    data = json.loads(out)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["incident_id"] == "INC-CLI-001"


def test_cli_incidents_by_id(capsys, populated_db):
    """Test attacktrace incidents --id displays detailed narrative and graph."""
    code = main(["incidents", "--id", "INC-CLI-001", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Chronological Investigation Log:" in out
    assert "ATTACK GRAPH" in out


def test_cli_incidents_by_id_json(capsys, populated_db):
    """Test attacktrace incidents --id with --json."""
    code = main(["incidents", "--id", "INC-CLI-001", "--json", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 0
    data = json.loads(out)
    assert data["incident_id"] == "INC-CLI-001"


def test_cli_incidents_not_found(capsys, populated_db):
    """Test attacktrace incidents --id with invalid ID returns error."""
    code = main(["incidents", "--id", "NON-EXISTENT-ID", "--db", populated_db.db_path], db=populated_db)
    out, _ = capsys.readouterr()
    assert code == 1
    assert "not found" in out


# ---------------------------------------------------------------------- #
# 6. Report Command Tests
# ---------------------------------------------------------------------- #


def test_cli_report_markdown(capsys, populated_db, tmp_path):
    """Test attacktrace report --id with markdown export."""
    out_file = str(tmp_path / "custom_report.md")
    code = main(
        ["report", "--id", "INC-CLI-001", "--format", "markdown", "--output", out_file, "--db", populated_db.db_path],
        db=populated_db,
    )
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS]" in out
    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "# ATTACKTRACE Forensic Incident Report" in content


def test_cli_report_json(capsys, populated_db, tmp_path):
    """Test attacktrace report --id with JSON dossier export."""
    out_file = str(tmp_path / "custom_dossier.json")
    code = main(
        ["report", "--id", "INC-CLI-001", "--format", "json", "--output", out_file, "--db", populated_db.db_path],
        db=populated_db,
    )
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS]" in out
    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        dossier = json.load(f)
    assert dossier["incident_id"] == "INC-CLI-001"


def test_cli_report_navigator(capsys, populated_db, tmp_path):
    """Test attacktrace report --id with MITRE Navigator layer export."""
    out_file = str(tmp_path / "custom_nav.json")
    code = main(
        ["report", "--id", "INC-CLI-001", "--format", "navigator", "--output", out_file, "--db", populated_db.db_path],
        db=populated_db,
    )
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS]" in out
    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        layer = json.load(f)
    assert layer["domain"] == "enterprise-attack"


def test_cli_report_missing_id(capsys, populated_db):
    """Test attacktrace report without required --id."""
    code = main(["report", "--db", populated_db.db_path], db=populated_db)
    assert code != 0


# ---------------------------------------------------------------------- #
# 7. Mitigate Command Tests
# ---------------------------------------------------------------------- #


def test_cli_mitigate_script(capsys, populated_db, tmp_path):
    """Test attacktrace mitigate generates containment script."""
    out_file = str(tmp_path / "test_mitigate.sh")
    code = main(
        ["mitigate", "--id", "INC-CLI-001", "--platform", "linux", "--output", out_file, "--db", populated_db.db_path],
        db=populated_db,
    )
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS]" in out
    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "#!/bin/bash" in content


def test_cli_mitigate_rollback(capsys, populated_db, tmp_path):
    """Test attacktrace mitigate --rollback generates rollback script."""
    out_file = str(tmp_path / "test_rollback.ps1")
    code = main(
        [
            "mitigate",
            "--id",
            "INC-CLI-001",
            "--platform",
            "windows",
            "--rollback",
            "--output",
            out_file,
            "--db",
            populated_db.db_path,
        ],
        db=populated_db,
    )
    out, _ = capsys.readouterr()
    assert code == 0
    assert "[SUCCESS]" in out
    assert "rollback script" in out
    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "POWERSHELL" in content


def test_cli_mitigate_missing_id(capsys, populated_db):
    """Test attacktrace mitigate without required --id."""
    code = main(["mitigate", "--db", populated_db.db_path], db=populated_db)
    assert code != 0


# ---------------------------------------------------------------------- #
# 8. Invalid Subcommand Handling
# ---------------------------------------------------------------------- #


def test_cli_invalid_subcommand(capsys):
    """Test invalid subcommand exits with non-zero code."""
    code = main(["unknown_command_xyz"])
    assert code != 0


# ---------------------------------------------------------------------- #
# 9. Serve Command Mock
# ---------------------------------------------------------------------- #


def test_cli_serve_invokes_uvicorn(capsys):
    """Test attacktrace serve calls uvicorn.run with specified host/port."""
    with patch("uvicorn.run") as mock_run:
        code = main(["serve", "--host", "0.0.0.0", "--port", "9000"])
        assert code == 0
        mock_run.assert_called_once_with("src.api:app", host="0.0.0.0", port=9000, reload=False)

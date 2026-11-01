import json
import os
import pytest
from src.collector import LogCollector, stream_jsonl_chunks
from src.adapters import WindowsEventAdapter, SyslogAdapter, WebLogAdapter
from src.cli import main
from src.db import DatabaseManager
from src.pipeline import AttackTracePipeline


@pytest.fixture
def temp_db(tmp_path):
    """Creates an isolated temporary SQLite database."""
    db_file = str(tmp_path / "test_adapters.db")
    db = DatabaseManager(db_path=db_file)
    yield db
    db.close()


@pytest.fixture
def collector():
    return LogCollector()


# -----------------------------------------------------------------------------
# 1. Streaming JSONL Ingestion Tests
# -----------------------------------------------------------------------------


def test_streaming_jsonl_generator_chunking(tmp_path):
    """Test that stream_jsonl_chunks reads lines lazily in chunks with line numbers."""
    jsonl_file = str(tmp_path / "stream_test.jsonl")
    total_lines = 25
    with open(jsonl_file, "w", encoding="utf-8") as f:
        for i in range(1, total_lines + 1):
            f.write(f'{{"line": {i}, "timestamp": "2026-11-01T10:00:{i:02d}Z", "source_type": "app", "event_type": "TEST"}}\n')

    chunks = list(stream_jsonl_chunks(jsonl_file, chunk_size=10))
    # Should yield 3 chunks: 10, 10, 5
    assert len(chunks) == 3
    assert len(chunks[0]) == 10
    assert len(chunks[1]) == 10
    assert len(chunks[2]) == 5

    # Check line numbers
    assert chunks[0][0][0] == 1
    assert chunks[0][9][0] == 10
    assert chunks[2][-1][0] == 25


def test_ingest_jsonl_with_valid_and_malformed_lines(collector, tmp_path):
    """Test streaming .jsonl ingestion with valid lines, blank lines, and malformed JSON."""
    jsonl_file = str(tmp_path / "mixed.jsonl")
    lines = [
        # Line 1: Valid UnifiedEvent
        json.dumps({
            "timestamp": "2026-11-01T10:00:00Z",
            "source_type": "auth",
            "event_type": "LOGIN_SUCCESS",
            "user": "alice",
            "source_ip": "10.0.0.1",
        }),
        # Line 2: Empty line (should be skipped)
        "",
        # Line 3: Malformed JSON syntax
        '{"timestamp": "2026-11-01T10:01:00Z", "source_type": BROKEN JSON',
        # Line 4: Valid Windows Event in JSONL
        json.dumps({
            "EventID": 4624,
            "TargetUserName": "bob",
            "IpAddress": "10.0.0.2",
            "TimeCreated": "2026-11-01T10:02:00Z",
            "LogonType": 3,
        }),
        # Line 5: Missing required field (not valid UnifiedEvent)
        json.dumps({"invalid": "payload_without_timestamp"}),
        # Line 6: Valid UnifiedEvent
        json.dumps({
            "timestamp": "2026-11-01T10:03:00Z",
            "source_type": "web",
            "event_type": "API_REQUEST",
            "resource": "/api/v1/health",
        }),
    ]
    with open(jsonl_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    valid_count, dropped_count = collector.ingest_jsonl_file(jsonl_file, chunk_size=2)

    assert valid_count == 3
    assert dropped_count == 2
    assert len(collector.valid_events) == 3
    assert len(collector.dropped_events) == 2

    # Verify dropped event metadata (line numbers and reasons)
    dropped_lines = [d["line_number"] for d in collector.dropped_events]
    assert 3 in dropped_lines  # Broken JSON
    assert 5 in dropped_lines  # Missing required fields

    # Verify provenance
    for ev in collector.valid_events:
        assert ev.raw_payload.get("_provenance_file") == os.path.abspath(jsonl_file)
        assert ev.raw_payload.get("is_demo") is False


# -----------------------------------------------------------------------------
# 2. Windows Security Event Log Adapter Tests
# -----------------------------------------------------------------------------


def test_windows_event_4624_login_success():
    """Test Event ID 4624 normalization extracts TargetUserName, IpAddress, and LogonType."""
    record = {
        "EventID": 4624,
        "TimeCreated": "2026-11-01T08:15:00Z",
        "TargetUserName": "admin_svc",
        "IpAddress": "192.168.1.150",
        "LogonType": 3,
        "WorkstationName": "WKST-001",
    }
    event = WindowsEventAdapter.normalize(record)
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.source_type == "windows_event"
    assert event.user == "admin_svc"
    assert event.source_ip == "192.168.1.150"
    assert "LogonType:3" in event.resource
    assert event.status == 200
    assert event.raw_payload["is_demo"] is False


def test_windows_event_4625_login_failed():
    """Test Event ID 4625 normalization extracts TargetUserName, IpAddress, and sets 401."""
    record = {
        "EventID": 4625,
        "TimeCreated": "2026-11-01T08:16:22Z",
        "TargetUserName": "administrator",
        "IpAddress": "198.51.100.44",
        "FailureReason": "Unknown user name or bad password.",
        "Status": "0xC000006D",
    }
    event = WindowsEventAdapter.normalize(record)
    assert event.event_type == "LOGIN_FAILED"
    assert event.source_type == "windows_event"
    assert event.user == "administrator"
    assert event.source_ip == "198.51.100.44"
    assert event.status == 401
    assert "Unknown user name" in event.resource


def test_windows_event_4688_process_creation():
    """Test Event ID 4688 normalization extracts NewProcessName, CommandLine, SubjectUserName."""
    record = {
        "Event": {
            "System": {
                "EventID": 4688,
                "TimeCreated": {"@SystemTime": "2026-11-01T08:20:00Z"},
                "Computer": "DC01.corp.local",
            },
            "EventData": {
                "SubjectUserName": "svc_installer",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgA...",
            },
        }
    }
    event = WindowsEventAdapter.normalize(record)
    assert event.event_type == "PROCESS_CREATION"
    assert event.source_type == "windows_event"
    assert event.user == "svc_installer"
    assert "powershell.exe" in event.resource
    assert "CommandLine" in event.raw_payload
    assert event.status == 0


def test_windows_event_4672_privilege_assigned():
    """Test Event ID 4672 normalization extracts SubjectUserName and PrivilegeList."""
    record = {
        "EventID": 4672,
        "TimeCreated": "2026-11-01T08:25:00Z",
        "SubjectUserName": "SYSTEM",
        "PrivilegeList": "SeSecurityPrivilege\nSeBackupPrivilege\nSeRestorePrivilege",
    }
    event = WindowsEventAdapter.normalize(record)
    assert event.event_type == "PRIVILEGE_ASSIGNED"
    assert event.source_type == "windows_event"
    assert event.user == "SYSTEM"
    assert "SeSecurityPrivilege" in event.resource
    assert event.status == 0


# -----------------------------------------------------------------------------
# 3. Syslog Adapter Tests (RFC 3164 and RFC 5424)
# -----------------------------------------------------------------------------


def test_syslog_ssh_failed_password():
    """Test Syslog parsing for SSH failed logins (RFC 3164 format)."""
    line = "<38>Oct 24 14:02:10 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 44822 ssh2"
    event = SyslogAdapter.parse_line(line)
    assert event.event_type == "LOGIN_FAILED"
    assert event.source_type == "syslog"
    assert event.user == "root"
    assert event.source_ip == "192.168.1.100"
    assert event.status == 401
    assert event.resource == "sshd"
    assert event.raw_payload["pri"] == 38
    assert event.raw_payload["hostname"] == "web01"


def test_syslog_ssh_failed_invalid_user():
    """Test Syslog parsing for SSH invalid user failure."""
    line = "<86>Oct 24 14:05:00 gw sshd[5678]: Failed password for invalid user admin from 203.0.113.88 port 51100 ssh2"
    event = SyslogAdapter.parse_line(line)
    assert event.event_type == "LOGIN_FAILED"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.88"
    assert event.status == 401


def test_syslog_ssh_accepted_password_rfc5424():
    """Test Syslog parsing for SSH accepted login using RFC 5424 structured format."""
    line = "<165>1 2026-11-01T07:14:15.003Z server01 sshd 1234 ID47 - Accepted password for ubuntu from 10.0.0.50 port 52341 ssh2"
    event = SyslogAdapter.parse_line(line)
    assert event.event_type == "LOGIN_SUCCESS"
    assert event.source_type == "syslog"
    assert event.user == "ubuntu"
    assert event.source_ip == "10.0.0.50"
    assert event.status == 200
    assert event.timestamp == "2026-11-01T07:14:15.003Z"


def test_syslog_sudo_privilege_command():
    """Test Syslog parsing for sudo commands triggering PRIVILEGE_ASSIGNED."""
    line = "Nov 1 09:30:00 srv01 sudo:   operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/bin/chmod 777 /etc/shadow"
    event = SyslogAdapter.parse_line(line)
    assert event.event_type == "PRIVILEGE_ASSIGNED"
    assert event.user == "operator"
    assert "/bin/chmod 777" in event.resource


# -----------------------------------------------------------------------------
# 4. Web Server Access Log Adapter Tests
# -----------------------------------------------------------------------------


def test_web_log_sqli_payload_combined_format():
    """Test Web access log parsing for SQL injection URL parameter."""
    line = '192.168.1.10 - admin [01/Nov/2026:10:00:00 +0000] "GET /api/v1/users?id=1%27%20OR%201=1 HTTP/1.1" 200 4502 "http://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    event = WebLogAdapter.parse_line(line)
    assert event.source_type == "web"
    assert event.event_type == "API_REQUEST"
    assert event.source_ip == "192.168.1.10"
    assert event.user == "admin"
    assert event.status == 200
    # Decoded URL should expose SQL injection pattern
    assert "1' OR 1=1" in event.resource
    assert event.raw_payload["http_method"] == "GET"
    assert event.raw_payload["status_code"] == 200


def test_web_log_404_admin_probing():
    """Test Web access log parsing for 404 scanning/probing."""
    line = '203.0.113.5 - - [01/Nov/2026:10:05:00 +0000] "GET /wp-admin/config.php HTTP/1.1" 404 153 "-" "sqlmap/1.5"'
    event = WebLogAdapter.parse_line(line)
    assert event.source_type == "web"
    assert event.event_type == "API_REQUEST"
    assert event.source_ip == "203.0.113.5"
    assert event.user is None  # '-' converted to None
    assert event.status == 404
    assert event.resource == "/wp-admin/config.php"
    assert "sqlmap" in event.raw_payload["user_agent"]


def test_web_log_common_log_format():
    """Test Common Log Format parsing (without referer or user-agent)."""
    line = '127.0.0.1 - devuser [10/Oct/2026:13:55:36 -0700] "POST /auth/login HTTP/1.0" 200 2326'
    event = WebLogAdapter.parse_line(line)
    assert event.source_type == "web"
    assert event.event_type == "API_REQUEST"
    assert event.source_ip == "127.0.0.1"
    assert event.user == "devuser"
    assert event.status == 200
    assert event.resource == "/auth/login"


# -----------------------------------------------------------------------------
# 5. Pipeline End-to-End & CLI Ingestion Tests
# -----------------------------------------------------------------------------


def test_pipeline_with_web_and_syslog_telemetry(temp_db, tmp_path):
    """Test running AttackTracePipeline on a web access log file with SQLi attacks."""
    web_log = str(tmp_path / "access.log")
    with open(web_log, "w", encoding="utf-8") as f:
        f.write('185.220.101.5 - - [01/Nov/2026:10:00:00 +0000] "GET /products?id=1%27%20UNION%20SELECT%20password%20FROM%20users--%20 HTTP/1.1" 200 4096 "-" "curl/7.68.0"\n')
        f.write('185.220.101.5 - - [01/Nov/2026:10:01:00 +0000] "GET /admin/export?type=credentials HTTP/1.1" 200 1024000 "-" "curl/7.68.0"\n')

    pipeline = AttackTracePipeline(db=temp_db)
    incidents = pipeline.run_pipeline(web_log, file_type="web", is_demo=False)

    assert len(pipeline.collector.valid_events) == 2
    assert len(pipeline.enriched_events) == 2
    # Verify events are tagged as non-demo
    for ev in pipeline.enriched_events:
        assert ev.base_event.raw_payload.get("is_demo") is False

    # Check that SQLi indicator was matched from decoded URL
    matched_indicators = [ind for ev in pipeline.enriched_events for ind in ev.indicators]
    assert "SQL_INJECTION_PATTERN" in matched_indicators


def test_cli_ingest_jsonl_flag(capsys, temp_db, tmp_path):
    """Test CLI command 'attacktrace ingest' with --type jsonl."""
    jsonl_path = str(tmp_path / "test.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        f.write(json.dumps({
            "timestamp": "2026-11-01T10:00:00Z",
            "source_type": "auth",
            "event_type": "LOGIN_FAILED",
            "user": "root",
            "source_ip": "198.51.100.11",
            "status": 401,
        }) + "\n")

    code = main(["ingest", jsonl_path, "--type", "jsonl", "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Ingested logs (L1):" in out
    assert "1" in out
    assert "jsonl" in out


def test_cli_ingest_syslog_file(capsys, temp_db, tmp_path):
    """Test CLI command 'attacktrace ingest' with Syslog telemetry."""
    syslog_path = str(tmp_path / "auth.syslog")
    with open(syslog_path, "w", encoding="utf-8") as f:
        f.write("<38>Oct 24 14:02:10 web01 sshd[1234]: Failed password for root from 185.220.101.5 port 44822 ssh2\n")
        f.write("<38>Oct 24 14:02:15 web01 sshd[1235]: Failed password for root from 185.220.101.5 port 44824 ssh2\n")

    code = main(["ingest", syslog_path, "--type", "syslog", "--db", temp_db.db_path], db=temp_db)
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Ingested logs (L1):" in out
    assert "2" in out
    assert "syslog" in out

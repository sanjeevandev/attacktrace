import json
import pytest
from src.collector import LogCollector
from src.models import UnifiedEvent


def test_successful_parsing(tmp_path):
    """
    Test successful parsing of valid records, checking field extraction and UUID generation.
    """
    test_data = [
        {
            "timestamp": "2026-08-23T12:00:00Z",
            "source_type": "auth",
            "event_type": "LOGIN_SUCCESS",
            "user": "sanjeeva",
            "source_ip": "192.168.1.1",
            "resource": "/home",
            "status": 200,
            "raw_payload": {"info": "test"}
        },
        {
            "timestamp": "2026-08-23T12:01:00Z",
            "source_type": "web",
            "event_type": "API_REQUEST",
            "raw_payload": {}
        }
    ]
    
    file_path = tmp_path / "valid_logs.json"
    file_path.write_text(json.dumps(test_data))

    collector = LogCollector()
    valid_count, dropped_count = collector.ingest_json_file(str(file_path))

    assert valid_count == 2
    assert dropped_count == 0
    assert len(collector.valid_events) == 2
    assert len(collector.dropped_events) == 0

    event1 = collector.valid_events[0]
    assert event1.timestamp == "2026-08-23T12:00:00Z"
    assert event1.source_type == "auth"
    assert event1.event_type == "LOGIN_SUCCESS"
    assert event1.user == "sanjeeva"
    assert event1.source_ip == "192.168.1.1"
    assert event1.resource == "/home"
    assert event1.status == 200
    assert event1.raw_payload == {"info": "test"}
    # UUID check
    assert len(event1.event_id) == 36  # Standard UUID length

    event2 = collector.valid_events[1]
    assert event2.timestamp == "2026-08-23T12:01:00Z"
    assert event2.source_type == "web"
    assert event2.event_type == "API_REQUEST"
    assert event2.user is None
    assert event2.source_ip is None
    assert event2.resource is None
    assert event2.status is None
    assert event2.raw_payload == {}
    assert len(event2.event_id) == 36


def test_dropped_malformed_records(tmp_path):
    """
    Test that malformed records are dropped and cataloged correctly.
    """
    test_data = [
        # Missing timestamp
        {
            "source_type": "auth",
            "event_type": "LOGIN_SUCCESS",
            "user": "test_user"
        },
        # Missing source_type
        {
            "timestamp": "2026-08-23T12:00:00Z",
            "event_type": "LOGIN_SUCCESS",
            "user": "test_user"
        },
        # Missing event_type
        {
            "timestamp": "2026-08-23T12:00:00Z",
            "source_type": "auth",
            "user": "test_user"
        },
        # Valid record
        {
            "timestamp": "2026-08-23T12:00:00Z",
            "source_type": "web",
            "event_type": "API_REQUEST"
        },
        # Non-dictionary item in array
        "not-a-dict"
    ]

    file_path = tmp_path / "malformed_logs.json"
    file_path.write_text(json.dumps(test_data))

    collector = LogCollector()
    valid_count, dropped_count = collector.ingest_json_file(str(file_path))

    assert valid_count == 1
    assert dropped_count == 4
    assert len(collector.valid_events) == 1
    assert len(collector.dropped_events) == 4

    # Verify invalid details are captured
    drop1 = collector.dropped_events[0]
    assert "timestamp" in drop1["error"]
    assert drop1["record"]["user"] == "test_user"

    drop2 = collector.dropped_events[1]
    assert "source_type" in drop2["error"]

    drop3 = collector.dropped_events[2]
    assert "event_type" in drop3["error"]

    drop4 = collector.dropped_events[3]
    assert drop4["record"] == "not-a-dict"
    assert "must be a dictionary" in drop4["error"]


def test_get_summary(tmp_path):
    """
    Test event type summary counting.
    """
    test_data = [
        {"timestamp": "2026-08-23T12:00:00Z", "source_type": "auth", "event_type": "LOGIN_SUCCESS"},
        {"timestamp": "2026-08-23T12:01:00Z", "source_type": "auth", "event_type": "LOGIN_SUCCESS"},
        {"timestamp": "2026-08-23T12:02:00Z", "source_type": "auth", "event_type": "LOGIN_FAILED"},
        {"timestamp": "2026-08-23T12:03:00Z", "source_type": "web", "event_type": "API_REQUEST"},
    ]

    file_path = tmp_path / "summary_logs.json"
    file_path.write_text(json.dumps(test_data))

    collector = LogCollector()
    collector.ingest_json_file(str(file_path))

    summary = collector.get_summary()
    assert summary == {
        "LOGIN_SUCCESS": 2,
        "LOGIN_FAILED": 1,
        "API_REQUEST": 1
    }


def test_file_not_found_handling():
    """
    Test that LogCollector raises FileNotFoundError if the file does not exist.
    """
    collector = LogCollector()
    with pytest.raises(FileNotFoundError):
        collector.ingest_json_file("non_existent_file.json")


def test_clear(tmp_path):
    """
    Test clearing logs.
    """
    test_data = [
        {"timestamp": "2026-08-23T12:00:00Z", "source_type": "auth", "event_type": "LOGIN_SUCCESS"}
    ]
    file_path = tmp_path / "clear_logs.json"
    file_path.write_text(json.dumps(test_data))

    collector = LogCollector()
    collector.ingest_json_file(str(file_path))
    assert len(collector.valid_events) == 1

    collector.clear()
    assert len(collector.valid_events) == 0
    assert len(collector.dropped_events) == 0

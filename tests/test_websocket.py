import json
import pytest
from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)


def test_websocket_handshake():
    """
    Verifies that a WebSocket client can establish a connection with the /ws/alerts endpoint.
    """
    with client.websocket_connect("/ws/alerts") as websocket:
        # Handshake should complete and keep the socket open
        pass


def test_websocket_broadcast_on_trigger():
    """
    Validates that posting raw logs to /api/v1/stream/trigger broadcasts
    both NEW_EVENT and METRIC_UPDATE payloads to listening sockets.
    """
    sample_log = {
        "timestamp": "2026-08-23T18:00:00Z",
        "source_type": "web",
        "event_type": "SUSPICIOUS_WEB_RECON",
        "user": "admin",
        "source_ip": "185.220.101.99",
        "resource": "/.git/config",
        "status": 404,
        "raw_payload": {}
    }

    with client.websocket_connect("/ws/alerts") as websocket:
        # Post to stream trigger to ingest logs
        response = client.post("/api/v1/stream/trigger", json=[sample_log])
        assert response.status_code == 200

        # Receive broadcast messages
        messages = []
        for _ in range(4):
            try:
                msg = websocket.receive_json()
                messages.append(msg)
                if msg["type"] == "METRIC_UPDATE":
                    break
            except Exception:
                break

        # Validate that the necessary WebSocket message types were broadcasted
        msg_types = [m["type"] for m in messages]
        assert "NEW_EVENT" in msg_types
        assert "METRIC_UPDATE" in msg_types

        # Verify content details of the event payload
        event_msg = next(m for m in messages if m["type"] == "NEW_EVENT")
        assert event_msg["payload"]["base_event"]["source_ip"] == "185.220.101.99"

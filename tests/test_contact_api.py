import os
import pytest
from fastapi.testclient import TestClient

from src.api import app, db_manager, pipeline
from src.db import DatabaseManager


@pytest.fixture
def client():
    return TestClient(app)


def test_get_contact_serves_html(client):
    """
    Test that GET /contact returns HTTP 200 and text/html content,
    and includes essential brand and structural elements.
    """
    response = client.get("/contact")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    html = response.text

    # HTML doctype and brand titles
    assert "<!DOCTYPE html>" in html
    assert "ATTACKTRACE" in html
    assert "Zero Latency" in html
    assert "Zero-Latency Threat Reconstruction for Modern SOCs." in html

    # Proof badges
    assert "v1.0.0 Production Ready" in html
    assert "MITRE ATT&amp;CK Mapped" in html or "MITRE ATT&CK Mapped" in html
    assert "100% Offline-Safe" in html

    # Direct CTA link to dashboard
    assert "http://127.0.0.1:8000/dashboard" in html
    assert "Want to test it right now?" in html

    # Direct developer email & GitHub link
    assert "engineering@attacktrace.io" in html
    assert "https://github.com/sanjeevandev/attacktrace" in html

    # Inquiry tab selectors
    assert "Request SOC Demo" in html
    assert "Investor &amp; Academic Partnership" in html or "Investor & Academic Partnership" in html
    assert "Open-Source Collaboration" in html

    # Form fields and actions
    assert 'id="contact-form"' in html
    assert 'id="full_name"' in html
    assert 'id="email"' in html
    assert 'id="organization"' in html
    assert 'id="log_volume"' in html
    assert 'id="message"' in html
    assert "Transmit Inquiry" in html
    assert 'id="confirmation-banner"' in html


def test_post_inquiry_success(client):
    """
    Test that POST /api/v1/inquiry validates inputs, persists the record to SQLite,
    and returns HTTP 200 with status='success' and a unique ticket_id starting with 'INQ-'.
    """
    payload = {
        "full_name": "Marcus Kane",
        "email": "marcus.kane@socdefense.corp",
        "organization": "SOC Defense Global",
        "inquiry_type": "Request SOC Demo",
        "log_volume": "1-50GB/day",
        "message": "We need sub-second kill chain graph reconstruction for our air-gapped datacenter."
    }

    response = client.post("/api/v1/inquiry", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "ticket_id" in data
    ticket_id = data["ticket_id"]
    assert ticket_id.startswith("INQ-")

    # Verify SQLite database persistence directly
    target_db = pipeline.db if (pipeline and pipeline.db) else db_manager
    inquiry_record = target_db.get_inquiry(ticket_id)
    assert inquiry_record is not None
    assert inquiry_record["inquiry_id"] == ticket_id
    assert inquiry_record["full_name"] == payload["full_name"]
    assert inquiry_record["email"] == payload["email"]
    assert inquiry_record["organization"] == payload["organization"]
    assert inquiry_record["inquiry_type"] == payload["inquiry_type"]
    assert inquiry_record["log_volume"] == payload["log_volume"]
    assert inquiry_record["message"] == payload["message"]
    assert inquiry_record["created_at"] is not None


def test_post_inquiry_alternative_types(client):
    """
    Test submitting inquiries with alternative tabs:
    Investor & Academic Partnership, and Open-Source Collaboration.
    """
    types_to_test = [
        "Investor & Academic Partnership",
        "Open-Source Collaboration"
    ]

    for inq_type in types_to_test:
        payload = {
            "full_name": f"Partner {inq_type}",
            "email": "partner@research.org",
            "organization": "National Cyber Institute",
            "inquiry_type": inq_type,
            "log_volume": "Enterprise",
            "message": f"Proposal for {inq_type} in threat correlation algorithms."
        }
        response = client.post("/api/v1/inquiry", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["ticket_id"].startswith("INQ-")


def test_post_inquiry_missing_email(client):
    """
    Test that submitting without an email returns HTTP 422 Unprocessable Entity.
    """
    payload = {
        "full_name": "No Email User",
        "organization": "Acme Corp",
        "inquiry_type": "Request SOC Demo",
        "log_volume": "<1GB/day",
        "message": "Inquiry without an email."
    }
    response = client.post("/api/v1/inquiry", json=payload)
    assert response.status_code in [400, 422]


def test_post_inquiry_invalid_email_format(client):
    """
    Test that an invalid email address triggers validation error HTTP 422.
    """
    payload = {
        "full_name": "Bad Email User",
        "email": "not-an-email-at-all",
        "organization": "Test Corp",
        "inquiry_type": "Request SOC Demo",
        "log_volume": "<1GB/day",
        "message": "Testing invalid email."
    }
    response = client.post("/api/v1/inquiry", json=payload)
    assert response.status_code in [400, 422]


def test_post_inquiry_missing_or_empty_message(client):
    """
    Test that missing, empty, or whitespace-only message triggers validation error HTTP 422.
    """
    # 1. Missing message field
    payload1 = {
        "full_name": "Missing Message",
        "email": "valid@corp.com"
    }
    res1 = client.post("/api/v1/inquiry", json=payload1)
    assert res1.status_code in [400, 422]

    # 2. Empty string message
    payload2 = {
        "full_name": "Empty Message",
        "email": "valid@corp.com",
        "message": ""
    }
    res2 = client.post("/api/v1/inquiry", json=payload2)
    assert res2.status_code in [400, 422]

    # 3. Whitespace-only message
    payload3 = {
        "full_name": "Whitespace Message",
        "email": "valid@corp.com",
        "message": "    "
    }
    res3 = client.post("/api/v1/inquiry", json=payload3)
    assert res3.status_code in [400, 422]


def test_post_inquiry_empty_full_name(client):
    """
    Test that missing or empty full_name triggers validation error HTTP 422.
    """
    payload = {
        "full_name": "   ",
        "email": "valid@corp.com",
        "message": "Valid message"
    }
    response = client.post("/api/v1/inquiry", json=payload)
    assert response.status_code in [400, 422]


def test_dashboard_header_contains_contact_link(client):
    """
    Test that templates/dashboard.html includes the [ Contact / Enterprise ] link
    pointing directly to /contact.
    """
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text
    assert 'href="/contact"' in html
    assert "Contact" in html

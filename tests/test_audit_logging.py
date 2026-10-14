import io
import json
import logging
import pytest
from datetime import datetime, timedelta
import jwt

from app.logging_config import log_audit, audit_logger
from app.auth import JWT_SECRET

class LogCaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        formatted = self.format(record)
        self.records.append(formatted)


@pytest.fixture
def capture_audit_logs():
    handler = LogCaptureHandler()
    from app.logging_config import AuditJsonFormatter
    handler.setFormatter(AuditJsonFormatter())
    audit_logger.addHandler(handler)
    yield handler.records
    audit_logger.removeHandler(handler)


def test_log_audit_produces_valid_structured_json():
    """Verify log_audit outputs valid single-line JSON with required top-level fields."""
    handler = LogCaptureHandler()
    from app.logging_config import AuditJsonFormatter
    handler.setFormatter(AuditJsonFormatter())
    audit_logger.addHandler(handler)

    try:
        log_audit(
            "TEST_EVENT",
            user_id=42,
            tenant_id=1,
            action="verify_format"
        )
        assert len(handler.records) == 1
        raw_log = handler.records[0]
        assert "\n" not in raw_log.strip()

        parsed = json.loads(raw_log)
        assert parsed["event"] == "TEST_EVENT"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "tenantguard.audit"
        assert "timestamp" in parsed
        assert parsed["message"] == "[TEST_EVENT]"
        assert parsed["user_id"] == 42
        assert parsed["tenant_id"] == 1
        assert parsed["action"] == "verify_format"
    finally:
        audit_logger.removeHandler(handler)


def test_warning_severity_events_auto_assigned():
    """Verify security failures/rejections automatically receive WARNING level."""
    handler = LogCaptureHandler()
    from app.logging_config import AuditJsonFormatter
    handler.setFormatter(AuditJsonFormatter())
    audit_logger.addHandler(handler)

    try:
        log_audit("AUTH_LOGIN_FAILED", username="malicious", ip="10.0.0.1")
        log_audit("DOCUMENT_ACCESS_DENIED", user_id=1, tenant_id=1, requested_document_id=99, ip="10.0.0.1")
        log_audit("UPLOAD_REJECTED", user_id=1, tenant_id=1, filename="bad.exe", reason="Unsupported", ip="10.0.0.1")
        log_audit("AUTH_TOKEN_EXPIRED", ip="10.0.0.1", username="expired_user")

        assert len(handler.records) == 4
        for record_str in handler.records:
            parsed = json.loads(record_str)
            assert parsed["level"] == "WARNING"
    finally:
        audit_logger.removeHandler(handler)


def test_audit_logs_emitted_during_login_and_access_denied(client, alice_token, capture_audit_logs):
    """Verify audit logs are emitted during live API calls."""
    # 1. Login success
    client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    login_events = [json.loads(r) for r in capture_audit_logs if "AUTH_LOGIN_SUCCESS" in r]
    assert len(login_events) >= 1
    login_entry = login_events[-1]
    assert login_entry["event"] == "AUTH_LOGIN_SUCCESS"
    assert login_entry["username"] == "alice"
    assert login_entry["tenant_id"] == 1
    assert "ip" in login_entry

    # 2. Login failed
    client.post("/auth/login", json={"username": "alice", "password": "wrong_password"})
    failed_events = [json.loads(r) for r in capture_audit_logs if "AUTH_LOGIN_FAILED" in r]
    assert len(failed_events) >= 1
    failed_entry = failed_events[-1]
    assert failed_entry["event"] == "AUTH_LOGIN_FAILED"
    assert failed_entry["username"] == "alice"
    assert failed_entry["level"] == "WARNING"

    # 3. Document access denied (cross-tenant IDOR attempt)
    # Alice (Tenant 1) attempts to view Bob's document (Tenant 2, doc_id=2)
    response = client.get("/documents/2", headers={"Authorization": f"Bearer {alice_token}"})
    assert response.status_code == 404
    denied_events = [json.loads(r) for r in capture_audit_logs if "DOCUMENT_ACCESS_DENIED" in r]
    assert len(denied_events) >= 1
    denied_entry = denied_events[-1]
    assert denied_entry["event"] == "DOCUMENT_ACCESS_DENIED"
    assert denied_entry["requested_document_id"] == 2
    assert denied_entry["tenant_id"] == 1
    assert denied_entry["level"] == "WARNING"

    # 4. Upload rejected (extension)
    bad_upload = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("malware.sh", io.BytesIO(b"echo 1"), "application/x-sh")}
    )
    assert bad_upload.status_code == 400
    rejected_events = [json.loads(r) for r in capture_audit_logs if "UPLOAD_REJECTED" in r]
    assert len(rejected_events) >= 1
    rejected_entry = rejected_events[-1]
    assert rejected_entry["event"] == "UPLOAD_REJECTED"
    assert rejected_entry["filename"] == "malware.sh"
    assert rejected_entry["level"] == "WARNING"


def test_audit_log_emitted_on_expired_token(client, capture_audit_logs):
    """Verify AUTH_TOKEN_EXPIRED audit event is recorded when an expired token is used."""
    expired_payload = {
        "sub": "alice",
        "user_id": 1,
        "tenant_id": 1,
        "role": "admin",
        "exp": (datetime.utcnow() - timedelta(days=10)).timestamp()
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm="HS256")

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401

    expired_events = [json.loads(r) for r in capture_audit_logs if "AUTH_TOKEN_EXPIRED" in r]
    assert len(expired_events) >= 1
    entry = expired_events[-1]
    assert entry["event"] == "AUTH_TOKEN_EXPIRED"
    assert entry["username"] == "alice"
    assert entry["level"] == "WARNING"
    assert "ip" in entry

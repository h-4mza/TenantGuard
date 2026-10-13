from datetime import datetime, timedelta
import jwt
import pytest

def test_jwt_secret_minimum_length_enforcement(monkeypatch):
    """
    Remediation Verification (FINDING-01 & FINDING-08):
    Starting without a secure JWT_SECRET (>= 32 chars) must raise a RuntimeError.
    """
    import importlib
    monkeypatch.setenv("JWT_SECRET", "short_weak_secret")
    with pytest.raises(RuntimeError, match="FATAL SECURITY CONFIGURATION ERROR"):
        import app.auth
        importlib.reload(app.auth)

    # Restore valid test secret for subsequent tests
    monkeypatch.setenv("JWT_SECRET", "t" * 64)
    import app.auth
    importlib.reload(app.auth)

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "TenantGuard"
    assert data["phase"] == "v0 (Vulnerable Initial Release)"

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_list_tenants(client):
    response = client.get("/auth/tenants")
    assert response.status_code == 200
    tenants = response.json()
    assert len(tenants) >= 3
    tenant_names = [t["name"] for t in tenants]
    assert "Acme Corp" in tenant_names
    assert "CyberDyne Systems" in tenant_names
    assert "Initech" in tenant_names

def test_register_and_login(client):
    # 1. Register new user for Tenant 3 (Initech)
    reg_response = client.post("/auth/register", json={
        "username": "peter_gibbons",
        "email": "peter@initech.com",
        "password": "office_space_pass",
        "tenant_id": 3
    })
    assert reg_response.status_code == 201
    user_data = reg_response.json()
    assert user_data["username"] == "peter_gibbons"
    assert user_data["tenant_id"] == 3

    # 2. Login with registered user
    login_response = client.post("/auth/login", json={
        "username": "peter_gibbons",
        "password": "office_space_pass"
    })
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # 3. Access protected /auth/me route
    token = token_data["access_token"]
    me_response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_response.status_code == 200
    assert me_response.json()["username"] == "peter_gibbons"

def test_vulnerability_jwt_no_expiration_check(client):
    """
    Vulnerability Verification (v0):
    A token with an expired 'exp' claim is accepted by the server because verify_exp=False.
    """
    # Forge a token that expired 1 year ago
    expired_payload = {
        "sub": "alice",
        "user_id": 1,
        "tenant_id": 1,
        "role": "admin",
        "exp": (datetime.utcnow() - timedelta(days=365)).timestamp()
    }
    expired_token = jwt.encode(expired_payload, "secret123", algorithm="HS256")

    # Call /auth/me with the expired token
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    # Because verify_exp=False is enabled in v0, the server accepts this expired token!
    assert response.status_code == 200
    assert response.json()["username"] == "alice"

import os
import shutil
import pytest
from fastapi.testclient import TestClient

# Set testing environment variables before importing app modules
os.environ["DATABASE_URL"] = "sqlite:///./test_tenantguard.db"
os.environ["UPLOAD_DIR"] = "./test_uploads"
os.environ["CHROMA_PERSIST_DIR"] = "./test_chroma"
os.environ["JWT_SECRET"] = "t" * 64  # Secure 64-character secret for test suite
os.environ["GEMINI_API_KEY"] = "mock"

from app.main import app
from app.database import init_db, engine
from app.models import Base

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    # Setup test directories and database
    os.makedirs("./test_uploads", exist_ok=True)
    os.makedirs("./test_chroma", exist_ok=True)
    init_db()

    yield

    # Teardown
    if os.path.exists("./test_tenantguard.db"):
        try:
            os.remove("./test_tenantguard.db")
        except Exception:
            pass
    if os.path.exists("./test_uploads"):
        shutil.rmtree("./test_uploads", ignore_errors=True)
    if os.path.exists("./test_chroma"):
        shutil.rmtree("./test_chroma", ignore_errors=True)

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture
def alice_token(client):
    """Authenticate Alice (Tenant 1 Admin) and return JWT."""
    response = client.post("/auth/login", json={
        "username": "alice",
        "password": "alice123"
    })
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture
def bob_token(client):
    """Authenticate Bob (Tenant 2 Admin) and return JWT."""
    response = client.post("/auth/login", json={
        "username": "bob",
        "password": "bob123"
    })
    assert response.status_code == 200
    return response.json()["access_token"]

import io
import os

def test_document_upload_and_list(client, alice_token):
    # Upload a document for Alice (Tenant 1)
    file_content = b"Financial report for Acme Corp 2026. Highly confidential."
    response = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("acme_report.txt", io.BytesIO(file_content), "text/plain")}
    )
    assert response.status_code == 201
    doc = response.json()
    assert doc["filename"] == "acme_report.txt"
    assert doc["tenant_id"] == 1

    # List documents
    list_response = client.get(
        "/documents",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert list_response.status_code == 200
    docs = list_response.json()
    assert len(docs) >= 1

def test_tenant_isolation_listing(client, alice_token, bob_token):
    """
    Remediation Verification (FINDING-03, FINDING-04):
    Alice (Tenant 1) cannot list documents belonging to Tenant 2 (CyberDyne Systems).
    Even if tenant_id query param is supplied, it only returns Tenant 1 documents.
    """
    response = client.get(
        "/documents?tenant_id=2",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    docs = response.json()
    assert all(d["tenant_id"] == 1 for d in docs)
    assert not any("cyberdyne" in d["filename"].lower() for d in docs)

def test_cross_tenant_document_access_returns_404(client, alice_token, bob_token):
    """
    Remediation Verification (FINDING-03, FINDING-04):
    Alice (Tenant 1) cannot read, download, or delete Bob's document (Tenant 2).
    Access attempts must return 404 (not 403) to prevent resource enumeration.
    """
    # Bob (Tenant 2) accesses his own seeded document (id=2) successfully
    bob_response = client.get(
        "/documents/2",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_response.status_code == 200
    assert bob_response.json()["tenant_id"] == 2

    # Alice (Tenant 1) attempts to read Bob's document metadata -> 404
    alice_read = client.get(
        "/documents/2",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert alice_read.status_code == 404

    # Alice attempts to download Bob's document -> 404
    alice_dl = client.get(
        "/documents/2/download",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert alice_dl.status_code == 404

    # Alice attempts to delete Bob's document -> 404
    alice_del = client.delete(
        "/documents/2",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert alice_del.status_code == 404

    # Bob's document is still intact
    bob_check = client.get(
        "/documents/2",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert bob_check.status_code == 200

def test_upload_ignores_client_tenant_id(client, alice_token):
    """
    Remediation Verification (FINDING-03):
    Upload ignores any client-supplied tenant_id and strictly assigns the document
    to current_user.tenant_id.
    """
    file_content = b"Attempting to upload to tenant 2 as alice"
    response = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("tenant_spoof.txt", io.BytesIO(file_content), "text/plain")},
        data={"tenant_id": 2}
    )
    assert response.status_code == 201
    doc = response.json()
    assert doc["tenant_id"] == 1

def test_vulnerability_path_traversal_upload(client, alice_token):
    """
    Vulnerability Verification (v0):
    File upload does not sanitize filename with os.path.basename,
    allowing relative path traversal strings.
    """
    traversal_filename = "subfolder/traversal_test.txt"
    file_content = b"Traversal test payload content."
    response = client.post(
        "/documents/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": (traversal_filename, io.BytesIO(file_content), "text/plain")}
    )
    assert response.status_code == 201
    doc = response.json()
    assert "subfolder" in doc["stored_path"]

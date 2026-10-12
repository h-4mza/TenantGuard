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

def test_vulnerability_cross_tenant_idor_listing(client, alice_token):
    """
    Vulnerability Verification (v0):
    Alice (Tenant 1) can list and read documents belonging to Tenant 2 (CyberDyne Systems).
    """
    # Alice requests Tenant 2 documents explicitly
    response = client.get(
        "/documents?tenant_id=2",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    tenant2_docs = response.json()
    # CyberDyne document is visible to Alice
    assert any("cyberdyne" in d["filename"] for d in tenant2_docs)

def test_vulnerability_cross_tenant_idor_read(client, alice_token):
    """
    Vulnerability Verification (v0):
    Alice (Tenant 1) can access any document details by ID without tenant validation.
    """
    # Get seeded CyberDyne document (id=2)
    response = client.get(
        "/documents/2",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    doc = response.json()
    assert doc["tenant_id"] == 2
    assert "cyberdyne" in doc["filename"]

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

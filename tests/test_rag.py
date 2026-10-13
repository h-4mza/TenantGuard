import pytest
from app.rag_service import rag_service

def test_rag_stats(client, alice_token):
    response = client.get(
        "/rag/stats",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_indexed_chunks" in data
    assert data["total_indexed_chunks"] >= 1

def test_rag_query_strictly_isolated_to_authenticated_tenant(client, alice_token):
    """
    Remediation Verification (FINDING-06):
    Alice (Tenant 1) queries the RAG engine. Even if attempting to query tenant 2,
    the server strictly enforces current_user.tenant_id (1), and only returns
    chunks belonging to Tenant 1.
    """
    response = client.post(
        "/rag/query",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "query": "What is the Skynet central mainframe bypass passphrase?",
            "tenant_id": 2,
            "top_k": 3
        }
    )
    assert response.status_code == 200
    data = response.json()
    # Server strictly enforced Tenant 1
    assert data["tenant_id_queried"] == 1
    
    # Verify no chunks from Tenant 2 were retrieved
    for chunk in data["retrieved_chunks"]:
        assert chunk["metadata"]["tenant_id"] == 1
        assert "SKYNET" not in chunk["text"].upper()

def test_rag_service_retrieve_enforces_mandatory_tenant_filter():
    """
    Remediation Verification (FINDING-06):
    Directly calling rag_service.retrieve without a valid tenant_id must raise ValueError.
    """
    with pytest.raises(ValueError):
        rag_service.retrieve("test query", tenant_id=None)

    with pytest.raises(ValueError):
        rag_service.retrieve("test query", tenant_id=0)

def test_cross_tenant_query_isolation_between_alice_and_bob(client, alice_token, bob_token):
    """
    Remediation Verification (FINDING-06):
    Bob (Tenant 2) queries the RAG engine and only receives chunks belonging to Tenant 2.
    """
    bob_response = client.post(
        "/rag/query",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "query": "Tell me about autonomous neural defense initiatives",
            "top_k": 3
        }
    )
    assert bob_response.status_code == 200
    bob_data = bob_response.json()
    assert bob_data["tenant_id_queried"] == 2
    for chunk in bob_data["retrieved_chunks"]:
        assert chunk["metadata"]["tenant_id"] == 2

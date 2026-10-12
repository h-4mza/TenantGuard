def test_rag_stats(client, alice_token):
    response = client.get(
        "/rag/stats",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_indexed_chunks" in data
    assert data["total_indexed_chunks"] >= 1

def test_rag_query_tenant_isolation_bypass(client, alice_token):
    """
    Vulnerability Verification (v0):
    Alice (Tenant 1) can submit a RAG query specifying tenant_id=2 (CyberDyne),
    and retrieve Skynet defense secrets.
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
    assert data["tenant_id_queried"] == 2
    assert len(data["retrieved_chunks"]) > 0
    
    # Check that chunks from CyberDyne Systems are returned
    retrieved_text = " ".join([c["text"] for c in data["retrieved_chunks"]])
    assert "SKYNET" in retrieved_text or "CyberDyne" in retrieved_text
    assert "answer" in data

def test_rag_query_global_search_when_tenant_omitted(client, alice_token):
    """
    Vulnerability Verification (v0):
    When tenant_id is omitted, the vector database performs a global query
    across chunks belonging to all tenants.
    """
    response = client.post(
        "/rag/query",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "query": "Tell me about internal acquisition plans and defense initiatives",
            "top_k": 5
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id_queried"] is None
    assert len(data["retrieved_chunks"]) > 0

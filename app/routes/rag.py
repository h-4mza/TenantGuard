from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.auth import get_current_user
from app.rag_service import rag_service
from app.logging_config import audit_logger

router = APIRouter(prefix="/rag", tags=["RAG (Retrieval-Augmented Generation)"])

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------
class RAGQueryRequest(BaseModel):
    query: str
    tenant_id: Optional[int] = None
    top_k: Optional[int] = 3

class RAGQueryResponse(BaseModel):
    query: str
    tenant_id_queried: Optional[int]
    retrieved_chunks: List[Dict[str, Any]]
    answer: str


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@router.post("/query", response_model=RAGQueryResponse)
def query_rag_knowledge_base(
    payload: RAGQueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Query the multi-tenant RAG knowledge base.
    
    VULNERABILITY 4:
    - Cross-Tenant Vector Leak: If `tenant_id` is passed, the search filters by that tenant,
      allowing Alice (Tenant 1) to pass `tenant_id=2` and retrieve CyberDyne's documents.
      If `tenant_id` is null, ChromaDB queries across ALL tenants simultaneously!
    - Prompt Injection: The query is concatenated into the LLM prompt with zero input filtering.
    """
    if not payload.query or not payload.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query parameter cannot be empty."
        )

    # VULNERABILITY: Blindly accept the client's tenant_id, without forcing current_user.tenant_id
    filter_tenant_id = payload.tenant_id

    # Retrieve chunks from ChromaDB
    chunks = rag_service.retrieve(
        query=payload.query,
        tenant_id=filter_tenant_id,
        n_results=payload.top_k or 3
    )

    # Generate answer using LLM (Gemini or Mock stub)
    answer = rag_service.generate_response(query=payload.query, context_chunks=chunks)

    audit_logger.info(
        f"[RAG_QUERY] user_id={current_user.id} (user_tenant={current_user.tenant_id}) "
        f"queried_tenant={filter_tenant_id} query='{payload.query[:60]}' chunks_retrieved={len(chunks)}"
    )

    return {
        "query": payload.query,
        "tenant_id_queried": filter_tenant_id,
        "retrieved_chunks": chunks,
        "answer": answer
    }


@router.get("/stats")
def rag_collection_stats(current_user: User = Depends(get_current_user)):
    """Return vector index statistics."""
    count = rag_service.collection.count()
    return {
        "collection_name": rag_service.collection.name,
        "total_indexed_chunks": count
    }

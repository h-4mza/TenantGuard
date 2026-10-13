import os
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Document, Tenant
from app.auth import get_current_user
from app.rag_service import rag_service
from app.logging_config import audit_logger

router = APIRouter(prefix="/documents", tags=["Documents Management"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------
class DocumentResponse(BaseModel):
    id: int
    tenant_id: int
    uploaded_by: int
    filename: str
    file_size: int
    stored_path: str
    created_at: datetime

    class Config:
        from_attributes = True


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@router.post("/upload", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a document for a tenant.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Client-supplied tenant_id parameter has been removed.
    - Tenant ID is strictly bound to current_user.tenant_id.
    """
    target_tenant_id = current_user.tenant_id

    # Verify that target tenant actually exists in DB
    target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id).first()
    if not target_tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target tenant {target_tenant_id} not found."
        )

    # Read complete raw content
    content = await file.read()
    file_size = len(content)

    stored_path = os.path.join(UPLOAD_DIR, file.filename)
    
    # Ensure directory exists if subdirectories were traversed
    parent_dir = os.path.dirname(stored_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    with open(stored_path, "wb") as f:
        f.write(content)

    # Record document in database
    new_doc = Document(
        tenant_id=target_tenant_id,
        uploaded_by=current_user.id,
        filename=file.filename,
        stored_path=stored_path,
        file_size=file_size
    )
    db.add(new_doc)
    db.commit()
    db.refresh(new_doc)

    # Attempt to index text content in ChromaDB for RAG
    try:
        text_content = content.decode("utf-8", errors="ignore")
        if text_content.strip():
            rag_service.index_document(
                document_id=new_doc.id,
                tenant_id=target_tenant_id,
                filename=new_doc.filename,
                content=text_content
            )
    except Exception as e:
        audit_logger.warning(f"Could not vectorize file {new_doc.filename}: {e}")

    audit_logger.info(
        f"[DOCUMENT_UPLOAD] doc_id={new_doc.id} filename='{new_doc.filename}' "
        f"assigned_tenant={target_tenant_id} uploaded_by={current_user.id} size={file_size}"
    )

    return new_doc


@router.get("", response_model=List[DocumentResponse])
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List documents.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by current_user.tenant_id.
    - Never returns documents from other tenants, regardless of query parameters.
    """
    docs = db.query(Document).filter(Document.tenant_id == current_user.tenant_id).all()
    audit_logger.info(
        f"[DOCUMENT_LIST] user_id={current_user.id} tenant_id={current_user.tenant_id} returned_count={len(docs)}"
    )
    return docs


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get metadata for a specific document.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {document_id} not found."
        )

    audit_logger.info(
        f"[DOCUMENT_VIEW] user_id={current_user.id} (tenant {current_user.tenant_id}) accessed doc_id={doc.id}"
    )
    return doc


@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Download physical document file.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {document_id} not found."
        )

    if not os.path.exists(doc.stored_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File on disk not found."
        )

    audit_logger.info(
        f"[DOCUMENT_DOWNLOAD] user_id={current_user.id} (tenant {current_user.tenant_id}) downloaded doc_id={doc.id}"
    )
    return FileResponse(
        path=doc.stored_path,
        filename=doc.filename,
        media_type="application/octet-stream"
    )


@router.delete("/{document_id}", status_code=status.HTTP_200_OK)
def delete_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a document.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {document_id} not found."
        )

    # Delete from ChromaDB
    rag_service.delete_document(document_id)

    # Delete physical file if present
    if os.path.exists(doc.stored_path):
        try:
            os.remove(doc.stored_path)
        except Exception as e:
            audit_logger.warning(f"Could not remove file {doc.stored_path}: {e}")

    db.delete(doc)
    db.commit()

    audit_logger.info(
        f"[DOCUMENT_DELETE] user_id={current_user.id} (tenant {current_user.tenant_id}) deleted doc_id={doc.id}"
    )
    return {"status": "success", "message": f"Document {document_id} deleted."}

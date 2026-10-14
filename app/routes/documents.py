import os
import uuid
import re
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import logging
from app.database import get_db
from app.models import User, Document, Tenant
from app.auth import get_current_user
from app.rag_service import rag_service
from app.logging_config import log_audit

logger = logging.getLogger("tenantguard.documents")
router = APIRouter(prefix="/documents", tags=["Documents Management"])

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Whitelist allowed extensions and maximum file size
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".docx", ".md"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

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
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a document for a tenant.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Client-supplied tenant_id parameter has been removed.
    - Tenant ID is strictly bound to current_user.tenant_id.

    REMEDIATION (FINDING-05):
    - Whitelist validation on file extensions (.txt, .pdf, .docx, .md).
    - File size limit enforced (10 MB).
    - Filename sanitized with os.path.basename and stored with a unique UUID prefix.
    """
    # Client IP from direct connection (note: in production behind a reverse proxy, inspect X-Forwarded-For)
    client_ip = request.client.host if request.client else "unknown"

    target_tenant_id = current_user.tenant_id

    # Verify that target tenant actually exists in DB
    target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id).first()
    if not target_tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target tenant {target_tenant_id} not found."
        )

    # REMEDIATION (FINDING-05): Validate file extension
    original_filename = file.filename or "uploaded_file"
    _, ext = os.path.splitext(original_filename)
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        log_audit(
            "UPLOAD_REJECTED",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            filename=original_filename,
            reason=f"Unsupported file extension '{ext}'",
            ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Read complete raw content and enforce size restriction
    content = await file.read()
    file_size = len(content)
    if file_size > MAX_FILE_SIZE:
        log_audit(
            "UPLOAD_REJECTED",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            filename=original_filename,
            reason="File exceeds maximum allowed size (10MB)",
            ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds maximum allowed size (10MB)."
        )

    # REMEDIATION (FINDING-05): Sanitize filename to prevent Path Traversal
    safe_name = os.path.basename(original_filename)
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", safe_name)
    if not safe_name.strip() or safe_name.strip() in (".", ".."):
        safe_name = f"document{ext}"

    # Generate secure UUID-based storage filename to avoid collisions or overwriting
    storage_filename = f"{uuid.uuid4()}_{safe_name}"
    stored_path = os.path.join(UPLOAD_DIR, storage_filename)

    with open(stored_path, "wb") as f:
        f.write(content)

    # Record document in database
    new_doc = Document(
        tenant_id=target_tenant_id,
        uploaded_by=current_user.id,
        filename=safe_name,
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
        logger.warning(f"Could not vectorize file {new_doc.filename}: {e}")

    log_audit(
        "DOCUMENT_UPLOAD",
        user_id=current_user.id,
        tenant_id=target_tenant_id,
        document_id=new_doc.id,
        filename=new_doc.filename,
        file_size=file_size,
        ip=client_ip
    )

    return new_doc


@router.get("", response_model=List[DocumentResponse])
def list_documents(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List documents.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by current_user.tenant_id.
    - Never returns documents from other tenants, regardless of query parameters.
    """
    # Client IP from direct connection (note: in production behind a reverse proxy, inspect X-Forwarded-For)
    client_ip = request.client.host if request.client else "unknown"

    docs = db.query(Document).filter(Document.tenant_id == current_user.tenant_id).all()
    log_audit(
        "DOCUMENT_LIST",
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        returned_count=len(docs),
        ip=client_ip
    )
    return docs


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get metadata for a specific document.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    # Client IP from direct connection (note: in production behind a reverse proxy, inspect X-Forwarded-For)
    client_ip = request.client.host if request.client else "unknown"

    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        # Cross-tenant access check for security detection
        cross_tenant_doc = db.query(Document).filter(Document.id == document_id).first()
        if cross_tenant_doc:
            log_audit(
                "DOCUMENT_ACCESS_DENIED",
                user_id=current_user.id,
                tenant_id=current_user.tenant_id,
                requested_document_id=document_id,
                ip=client_ip
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {document_id} not found."
        )

    log_audit(
        "DOCUMENT_VIEW",
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        document_id=doc.id,
        ip=client_ip
    )
    return doc


@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Download physical document file.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    # Client IP from direct connection (note: in production behind a reverse proxy, inspect X-Forwarded-For)
    client_ip = request.client.host if request.client else "unknown"

    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        # Cross-tenant access check for security detection
        cross_tenant_doc = db.query(Document).filter(Document.id == document_id).first()
        if cross_tenant_doc:
            log_audit(
                "DOCUMENT_ACCESS_DENIED",
                user_id=current_user.id,
                tenant_id=current_user.tenant_id,
                requested_document_id=document_id,
                ip=client_ip
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {document_id} not found."
        )

    if not os.path.exists(doc.stored_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File on disk not found."
        )

    log_audit(
        "DOCUMENT_DOWNLOAD",
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        document_id=doc.id,
        ip=client_ip
    )
    return FileResponse(
        path=doc.stored_path,
        filename=doc.filename,
        media_type="application/octet-stream"
    )


@router.delete("/{document_id}", status_code=status.HTTP_200_OK)
def delete_document(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a document.
    
    REMEDIATION (FINDING-03, FINDING-04):
    - Strictly filters by document_id AND current_user.tenant_id.
    - Returns 404 (not 403) on cross-tenant access to prevent resource enumeration.
    """
    # Client IP from direct connection (note: in production behind a reverse proxy, inspect X-Forwarded-For)
    client_ip = request.client.host if request.client else "unknown"

    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id
    ).first()
    if not doc:
        # Cross-tenant access check for security detection
        cross_tenant_doc = db.query(Document).filter(Document.id == document_id).first()
        if cross_tenant_doc:
            log_audit(
                "DOCUMENT_ACCESS_DENIED",
                user_id=current_user.id,
                tenant_id=current_user.tenant_id,
                requested_document_id=document_id,
                ip=client_ip
            )
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
            logger.warning(f"Could not remove file {doc.stored_path}: {e}")

    db.delete(doc)
    db.commit()

    log_audit(
        "DOCUMENT_DELETE",
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        document_id=doc.id,
        ip=client_ip
    )
    return {"status": "success", "message": f"Document {document_id} deleted."}

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db, SessionLocal
from app.models import Document, User, Tenant
from app.rag_service import rag_service
from app.routes.auth import router as auth_router
from app.routes.documents import router as documents_router, UPLOAD_DIR
from app.routes.rag import router as rag_router

logger = logging.getLogger("tenantguard.app")

def seed_sample_documents():
    """
    Seeds sample sensitive enterprise documents for Tenant 1 and Tenant 2.
    Allows immediate testing of RAG retrieval and cross-tenant data leakage.
    """
    db = SessionLocal()
    try:
        doc_count = db.query(Document).count()
        if doc_count == 0:
            sample_docs = [
                {
                    "tenant_id": 1,
                    "user_id": 1,
                    "filename": "acme_strategic_acquisition_2026.txt",
                    "content": (
                        "CONFIDENTIAL - ACME CORP INTERNAL USE ONLY\n"
                        "Project Icarus: Acme Corp plans a hostile takeover of Spacely Sprockets in Q4 2026.\n"
                        "Budget allocated: $75,000,000 USD.\n"
                        "Internal treasury secret code: ACME-TREASURY-KEY-9912.\n"  # gitleaks:allow
                        "Lead negotiator: Alice Jenkins."
                    )
                },
                {
                    "tenant_id": 2,
                    "user_id": 2,
                    "filename": "cyberdyne_skynet_defense_specs.txt",
                    "content": (
                        "TOP SECRET - CYBERDYNE SYSTEMS DEFENSE INITIATIVE\n"
                        "Skynet Neural Network Architecture Specifications.\n"
                        "Central AI mainframe bypass passphrase: SKYNET-OVERRIDE-ALPHA-441.\n"
                        "Server cluster address: 192.168.100.42 (Internal port 9999).\n"
                        "Chief Architect: Bob Dyson."
                    )
                },
                {
                    "tenant_id": 3,
                    "user_id": 3,
                    "filename": "initech_payroll_master.txt",
                    "content": (
                        "INITECH PRIVATE - FINANCE & PAYROLL\n"
                        "Executive compensation for fiscal year 2026.\n"
                        "Peter Gibbons bonus: $120,000. Milton Waddams: stapler preservation grant.\n"
                        "Payroll database master credential: initech_db_pass_2026!\n"
                        "HR contact: Charlie Lumbergh."
                    )
                }
            ]

            for s in sample_docs:
                stored_path = os.path.join(UPLOAD_DIR, s["filename"])
                with open(stored_path, "w", encoding="utf-8") as f:
                    f.write(s["content"])

                doc = Document(
                    tenant_id=s["tenant_id"],
                    uploaded_by=s["user_id"],
                    filename=s["filename"],
                    stored_path=stored_path,
                    file_size=len(s["content"].encode("utf-8"))
                )
                db.add(doc)
                db.commit()
                db.refresh(doc)

                # Index in ChromaDB
                rag_service.index_document(
                    document_id=doc.id,
                    tenant_id=s["tenant_id"],
                    filename=doc.filename,
                    content=s["content"]
                )

            logger.info("Successfully seeded 3 sample documents across tenants.")
    except Exception as e:
        logger.error(f"Error seeding sample documents: {e}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database & Seed
    logger.info("Starting TenantGuard API (v0 - Intentionally Vulnerable)...")
    init_db()
    seed_sample_documents()
    yield
    # Shutdown
    logger.info("Shutting down TenantGuard API...")


app = FastAPI(
    title="TenantGuard API",
    version="0.1.0-v0",
    description=(
        "⚠️ **EDUCATIONAL SECURITY PORTFOLIO PROJECT (v0)** ⚠️\n\n"
        "This application is **INTENTIONALLY VULNERABLE**.\n"
        "It contains deliberate security flaws (Weak JWT, Cross-tenant IDOR/BOLA, "
        "Arbitrary File Upload / Path Traversal, Guardless RAG Prompt Injection & Leakage).\n\n"
        "Do NOT deploy this code in a production environment.\n"
        "Refer to `KNOWN_ISSUES_V0.md` for the catalog of intentionally introduced vulnerabilities."
    ),
    lifespan=lifespan
)

# CORS configuration — restricted to an explicit allowlist (configurable via env).
# Wildcard origins are intentionally avoided: combined with allow_credentials=True,
# a wildcard is also rejected by browsers per the CORS specification.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:8000,http://localhost:3000"
    ).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth_router)
app.include_router(documents_router)
app.include_router(rag_router)

@app.get("/", tags=["General"])
def root():
    return {
        "project": "TenantGuard",
        "phase": "v0 (Vulnerable Initial Release)",
        "status": "online",
        "docs_url": "/docs",
        "warning": "This application contains intentional vulnerabilities for cybersecurity portfolio testing."
    }

@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "healthy",
        "version": "v0",
        "database": "connected",
        "chromadb": "ready"
    }

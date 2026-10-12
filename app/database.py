import os
import bcrypt
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, Tenant, User, Document

logger = logging.getLogger("tenantguard.app")

DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://tenantguard:tenantguard_secret@db:5432/tenantguard_db"
)

# Support SQLite fallback if testing locally outside Docker
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """FastAPI dependency to yield database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _hash_pwd(password: str) -> str:
    """Helper to hash seed passwords with bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def init_db():
    """Initializes database schema and seeds sample tenants & users if empty."""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        tenant_count = db.query(Tenant).count()
        if tenant_count == 0:
            logger.info("Database is empty. Seeding initial tenants and users...")

            # 1. Seed 3 Tenants
            t1 = Tenant(id=1, name="Acme Corp", description="Industrial defense and supply enterprise")
            t2 = Tenant(id=2, name="CyberDyne Systems", description="Autonomous neural networks and robotics")
            t3 = Tenant(id=3, name="Initech", description="Financial and enterprise software consulting")
            db.add_all([t1, t2, t3])
            db.commit()

            # 2. Seed Users for each tenant
            u1 = User(
                id=1,
                tenant_id=1,
                username="alice",
                email="alice@acme.com",
                hashed_password=_hash_pwd("alice123"),
                role="admin"
            )
            u2 = User(
                id=2,
                tenant_id=2,
                username="bob",
                email="bob@cyberdyne.com",
                hashed_password=_hash_pwd("bob123"),
                role="admin"
            )
            u3 = User(
                tenant_id=t3.id,
                username="charlie",
                email="charlie@initech.com",
                hashed_password=_hash_pwd("charlie123"),
                role="user"
            )
            db.add_all([u1, u2, u3])
            db.commit()

            logger.info("Seed completed: 3 tenants and 3 initial users created successfully.")

        # Always synchronize PostgreSQL sequences to max(id) to prevent duplicate key errors on new inserts
        if not DATABASE_URL.startswith("sqlite"):
            from sqlalchemy import text
            for table in ["tenants", "users", "documents"]:
                try:
                    db.execute(text(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), COALESCE((SELECT MAX(id) FROM {table}), 1));"))
                    db.commit()
                except Exception as seq_err:
                    logger.debug(f"Could not sync sequence for {table}: {seq_err}")
                    db.rollback()
    except Exception as e:
        logger.error(f"Error initializing or seeding database: {e}")
        db.rollback()
    finally:
        db.close()

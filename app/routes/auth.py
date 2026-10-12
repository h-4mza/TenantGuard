from datetime import timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Tenant
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
from app.logging_config import audit_logger

router = APIRouter(prefix="/auth", tags=["Authentication & Tenants"])

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------
class TenantCreate(BaseModel):
    name: str
    description: Optional[str] = None

class TenantResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

class UserRegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    tenant_id: int
    role: Optional[str] = "user"

class UserLoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    tenant_id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ------------------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------------------
@router.get("/tenants", response_model=List[TenantResponse])
def list_tenants(db: Session = Depends(get_db)):
    """List all available tenants in the SaaS platform."""
    tenants = db.query(Tenant).all()
    return tenants

@router.post("/tenants", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreate, db: Session = Depends(get_db)):
    """Create a new tenant organization."""
    existing = db.query(Tenant).filter(Tenant.name == payload.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant '{payload.name}' already exists."
        )
    tenant = Tenant(name=payload.name, description=payload.description)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    audit_logger.info(f"[TENANT_CREATED] id={tenant.id} name='{tenant.name}'")
    return tenant

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """Register a new user inside an existing tenant."""
    # Check tenant existence
    tenant = db.query(Tenant).filter(Tenant.id == payload.tenant_id).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant with id {payload.tenant_id} not found."
        )

    # Check unique username and email
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered."
        )

    new_user = User(
        tenant_id=payload.tenant_id,
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role or "user"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit_logger.info(
        f"[AUTH_REGISTER] user_id={new_user.id} username='{new_user.username}' tenant_id={new_user.tenant_id}"
    )
    return new_user

@router.post("/login", response_model=TokenResponse)
def login(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user and issue a JWT token.
    VULNERABILITY: Generates a token signed with a weak secret, which never expires.
    """
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        audit_logger.warning(f"[AUTH_LOGIN_FAILED] username='{payload.username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password."
        )

    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "tenant_id": user.tenant_id,
        "role": user.role
    }
    
    # 15 minutes exp claim generated, but decoded with verify_exp=False
    access_token = create_access_token(data=token_data, expires_delta=timedelta(minutes=15))

    audit_logger.info(
        f"[AUTH_LOGIN_SUCCESS] user_id={user.id} username='{user.username}' tenant_id={user.tenant_id}"
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Return profile details of the authenticated user."""
    return current_user

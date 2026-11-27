import re
import uuid
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, field_validator

from app.models.base import get_db
from app.models.entities import User, AuditEvent
from app.core.security import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter()

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

class UserRegisterRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if not EMAIL_REGEX.match(v_clean):
            raise ValueError("Invalid email format.")
        return v_clean

class UserLoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if not EMAIL_REGEX.match(v_clean):
            raise ValueError("Invalid email format.")
        return v_clean

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str

class UserProfileResponse(BaseModel):
    user_id: str
    email: str
    role: str
    is_active: bool

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    req: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    if len(req.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    # Check if user already exists
    stmt = select(User).where(User.email == req.email.lower().strip())
    res = await db.execute(stmt)
    if res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email is already registered."
        )

    user = User(
        id=str(uuid.uuid4()),
        email=req.email.lower().strip(),
        hashed_password=hash_password(req.password),
        role="analyst"
    )
    db.add(user)

    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="USER_REGISTERED",
        user_id=user.id,
        action=f"User registered with email {user.email}",
        resource_type="user",
        resource_id=user.id
    )
    db.add(audit)

    await db.commit()
    await db.refresh(user)

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        email=user.email,
        role=user.role
    )

@router.post("/login", response_model=AuthResponse)
async def login_user(
    req: UserLoginRequest,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == req.email.lower().strip())
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user or not verify_password(req.password, user.hashed_password):
        # Record failed login attempt in audit
        audit = AuditEvent(
            id=str(uuid.uuid4()),
            event_type="LOGIN_FAILED",
            user_id="anonymous",
            action=f"Failed login attempt for email {req.email}",
            resource_type="auth",
            details_json={"email": req.email}
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive."
        )

    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="LOGIN_SUCCESS",
        user_id=user.id,
        action=f"User logged in successfully",
        resource_type="auth",
        resource_id=user.id
    )
    db.add(audit)
    await db.commit()

    token = create_access_token(user_id=user.id, email=user.email, role=user.role)
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        email=user.email,
        role=user.role
    )

@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.id == current_user["sub"])
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return UserProfileResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        is_active=user.is_active
    )

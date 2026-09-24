import re
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import hash_password, verify_password, create_access_token
from app.db.session import get_db
from app.models.user import User
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])


# Request / Response Schemas
class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    full_name: Optional[str] = Field(None, max_length=255)
    role: Optional[str] = Field("user", description="Requested role: user, analyst, or admin")


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)


from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


@router.post("/register", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Registers a new user account with salted password hashing and audit logging."""
    client_ip = request.client.host if request.client else None
    email_clean = payload.email.lower().strip()

    # Check password complexity: at least 8 characters
    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters in length."
        )

    # Check email duplicate
    res = await db.execute(select(User).where(User.email == email_clean))
    existing_user = res.scalar_one_or_none()
    if existing_user:
        await log_audit_event(
            db=db,
            event_type="USER_REGISTER_FAILED",
            action="Account registration duplicate email attempt",
            user_email=email_clean,
            status="failure",
            client_ip=client_ip,
            details=f"Attempted duplicate email: {email_clean}",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists."
        )

    # Standardize initial role (admins can also be registered directly for dev, or user)
    assigned_role = payload.role if payload.role in ["user", "analyst", "admin"] else "user"

    hashed_pw = hash_password(payload.password)
    new_user = User(
        email=email_clean,
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    await log_audit_event(
        db=db,
        event_type="USER_REGISTER",
        action="User account registered successfully",
        user_id=new_user.id,
        user_email=new_user.email,
        status="success",
        client_ip=client_ip,
        details=f"Role assigned: {assigned_role}",
    )

    access_token = create_access_token(
        data={"sub": new_user.id, "email": new_user.email, "role": new_user.role}
    )

    return AuthTokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=new_user.id,
            email=new_user.email,
            full_name=new_user.full_name,
            role=new_user.role,
            is_active=new_user.is_active,
            created_at=new_user.created_at.isoformat(),
        ),
    )


@router.post("/login", response_model=AuthTokenResponse)
async def login(
    payload: UserLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticates user with email and password, returning signed JWT bearer token."""
    client_ip = request.client.host if request.client else None
    email_clean = payload.email.lower().strip()

    res = await db.execute(select(User).where(User.email == email_clean))
    user = res.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        await log_audit_event(
            db=db,
            event_type="USER_LOGIN_FAILED",
            action="Failed login attempt - invalid credentials",
            user_email=email_clean,
            status="failure",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email address or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        await log_audit_event(
            db=db,
            event_type="USER_LOGIN_BLOCKED",
            action="Login blocked for deactivated account",
            user_id=user.id,
            user_email=user.email,
            status="failure",
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact administrator.",
        )

    await log_audit_event(
        db=db,
        event_type="USER_LOGIN",
        action="User successfully authenticated",
        user_id=user.id,
        user_email=user.email,
        status="success",
        client_ip=client_ip,
    )

    access_token = create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role}
    )

    return AuthTokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat(),
        ),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile for currently authenticated user."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat(),
    )


@router.put("/profile", response_model=UserResponse)
async def update_profile(
    payload: UserProfileUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Updates user profile information or updates password."""
    client_ip = request.client.host if request.client else None

    if payload.full_name is not None:
        current_user.full_name = payload.full_name

    if payload.new_password:
        if not payload.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required to set a new password."
            )
        if not verify_password(payload.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password entered is incorrect."
            )
        if len(payload.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 8 characters long."
            )
        current_user.hashed_password = hash_password(payload.new_password)

    await db.commit()
    await db.refresh(current_user)

    await log_audit_event(
        db=db,
        event_type="USER_PROFILE_UPDATE",
        action="User profile or credentials updated",
        user_id=current_user.id,
        user_email=current_user.email,
        status="success",
        client_ip=client_ip,
    )

    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat(),
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Logs logout event."""
    client_ip = request.client.host if request.client else None
    await log_audit_event(
        db=db,
        event_type="USER_LOGOUT",
        action="User logged out",
        user_id=current_user.id,
        user_email=current_user.email,
        status="success",
        client_ip=client_ip,
    )
    return {"message": "Successfully logged out"}

import os
import time
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.audit import AuditLog
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/admin", tags=["Administration"], dependencies=[Depends(get_current_admin)])


class AdminUserItem(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    scan_count: int
    created_at: str


class AdminUserStatusUpdate(BaseModel):
    is_active: bool


class AdminUserRoleUpdate(BaseModel):
    role: str


class AuditLogItem(BaseModel):
    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    event_type: str
    action: str
    status: str
    client_ip: Optional[str] = None
    details: Optional[str] = None
    created_at: str


class ModelHealthInfo(BaseModel):
    model_name: str
    file_path: str
    exists: bool
    size_bytes: int


class SystemHealthDeepResponse(BaseModel):
    status: str
    db_latency_ms: float
    db_connected: bool
    active_users_count: int
    total_scans_recorded: int
    storage_writable: bool
    models_status: List[ModelHealthInfo]
    python_version: str


@router.get("/users", response_model=List[AdminUserItem])
async def list_users(db: AsyncSession = Depends(get_db)):
    """Lists all registered users with their scan activity counts."""
    res_users = await db.execute(select(User).order_by(desc(User.created_at)))
    users = res_users.scalars().all()

    user_items: List[AdminUserItem] = []
    for u in users:
        # Count scans created by this user
        res_scans = await db.execute(
            select(func.count(Scan.id)).where(Scan.user_id == u.id)
        )
        s_count = res_scans.scalar_one() or 0

        user_items.append(
            AdminUserItem(
                id=u.id,
                email=u.email,
                full_name=u.full_name,
                role=u.role,
                is_active=u.is_active,
                scan_count=s_count,
                created_at=u.created_at.isoformat(),
            )
        )
    return user_items


@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    payload: AdminUserStatusUpdate,
    admin_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Enables or disables a user account."""
    if user_id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account."
        )

    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = payload.is_active
    await db.commit()

    await log_audit_event(
        db=db,
        event_type="ADMIN_USER_STATUS_CHANGE",
        action=f"User {user.email} status set to {'active' if payload.is_active else 'inactive'}",
        user_id=admin_user.id,
        user_email=admin_user.email,
        status="success",
        details=f"Target User ID: {user.id}, is_active: {payload.is_active}",
    )
    return {"status": "ok", "user_id": user_id, "is_active": user.is_active}


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    payload: AdminUserRoleUpdate,
    admin_user: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Updates a user's role (user, analyst, admin)."""
    valid_roles = ["user", "analyst", "admin"]
    if payload.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    if user_id == admin_user.id and payload.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot demote themselves."
        )

    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = payload.role
    await db.commit()

    await log_audit_event(
        db=db,
        event_type="ADMIN_USER_ROLE_CHANGE",
        action=f"User {user.email} role updated to {payload.role}",
        user_id=admin_user.id,
        user_email=admin_user.email,
        status="success",
        details=f"Target User ID: {user.id}, new_role: {payload.role}",
    )
    return {"status": "ok", "user_id": user_id, "role": user.role}


@router.get("/audit-logs", response_model=List[AuditLogItem])
async def list_audit_logs(
    limit: int = 50,
    event_type: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Queries paginated security audit trails."""
    query = select(AuditLog)
    if event_type:
        query = query.where(AuditLog.event_type.ilike(f"%{event_type}%"))
    if user_email:
        query = query.where(AuditLog.user_email.ilike(f"%{user_email}%"))
    query = query.order_by(desc(AuditLog.created_at)).limit(limit)

    res = await db.execute(query)
    logs = res.scalars().all()
    return [
        AuditLogItem(
            id=log.id,
            user_id=log.user_id,
            user_email=log.user_email,
            event_type=log.event_type,
            action=log.action,
            status=log.status,
            client_ip=log.client_ip,
            details=log.details,
            created_at=log.created_at.isoformat(),
        )
        for log in logs
    ]


@router.get("/system/health", response_model=SystemHealthDeepResponse)
async def get_system_deep_health(db: AsyncSession = Depends(get_db)):
    """Performs deep operational diagnostics across database, storage, and models."""
    import sys

    # 1. Database latency check
    t0 = time.perf_counter()
    res = await db.execute(select(func.count(User.id)))
    active_users = res.scalar_one() or 0
    t1 = time.perf_counter()
    latency_ms = round((t1 - t0) * 1000, 2)

    # 2. Total scans
    res_scans = await db.execute(select(func.count(Scan.id)))
    total_scans = res_scans.scalar_one() or 0

    # 3. Storage check
    storage_path = Path(__file__).resolve().parent.parent.parent.parent / "storage" / "screenshots"
    storage_path.mkdir(parents=True, exist_ok=True)
    test_file = storage_path / ".healthcheck.tmp"
    writable = False
    try:
        test_file.write_text("ok")
        test_file.unlink()
        writable = True
    except Exception:
        writable = False

    # 4. Model artifacts check
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    model_paths = [
        ("URL RandomForest", project_root / "backend" / "app" / "ml" / "artifacts" / "url_model.joblib"),
        ("Visual MobileNetV2", project_root / "ml" / "vision" / "artifacts" / "mobilenetv2_phishguard.pth"),
        ("Fusion Stacking", project_root / "ml" / "fusion" / "artifacts" / "stacking_fusion_best.joblib"),
        ("Probability Calibrator", project_root / "ml" / "fusion" / "artifacts" / "probability_calibrator_best.joblib"),
    ]

    models_info: List[ModelHealthInfo] = []
    for name, p in model_paths:
        exists = p.exists()
        size = p.stat().st_size if exists else 0
        models_info.append(
            ModelHealthInfo(
                model_name=name,
                file_path=str(p.name),
                exists=exists,
                size_bytes=size,
            )
        )

    return SystemHealthDeepResponse(
        status="healthy" if writable else "degraded",
        db_latency_ms=latency_ms,
        db_connected=True,
        active_users_count=active_users,
        total_scans_recorded=total_scans,
        storage_writable=writable,
        models_status=models_info,
        python_version=sys.version.split()[0],
    )

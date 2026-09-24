from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.services.notification_service import (
    get_user_notifications,
    mark_notification_as_read,
    mark_all_notifications_as_read,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class NotificationResponse(BaseModel):
    id: str
    title: str
    message: str
    severity: str
    link: Optional[str] = None
    is_read: bool
    created_at: str


@router.get("", response_model=List[NotificationResponse])
async def list_notifications(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves recent security and platform notifications for the authenticated user."""
    notifications = await get_user_notifications(db, user_id=current_user.id, limit=limit)
    return [
        NotificationResponse(
            id=n.id,
            title=n.title,
            message=n.message,
            severity=n.severity,
            link=n.link,
            is_read=n.is_read,
            created_at=n.created_at.isoformat(),
        )
        for n in notifications
    ]


@router.patch("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Marks a specific notification as read."""
    success = await mark_notification_as_read(db, notification_id, user_id=current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    return {"status": "ok", "message": "Notification marked as read"}


@router.post("/mark-all-read")
async def mark_all_read(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Marks all unread notifications as read for current user."""
    updated_count = await mark_all_notifications_as_read(db, user_id=current_user.id)
    return {"status": "ok", "updated_count": updated_count}

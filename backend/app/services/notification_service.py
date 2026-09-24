from typing import Optional, List
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.logging import logger
from app.models.notification import Notification


async def create_notification(
    db: AsyncSession,
    title: str,
    message: str,
    severity: str = "info",
    user_id: Optional[str] = None,
    link: Optional[str] = None,
) -> Optional[Notification]:
    """Creates a persistent security or system notification."""
    try:
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            severity=severity,
            link=link,
            is_read=False,
        )
        db.add(notification)
        await db.commit()
        await db.refresh(notification)
        return notification
    except Exception as e:
        logger.error(f"Failed to create notification: {e}")
        await db.rollback()
        return None


async def get_user_notifications(
    db: AsyncSession,
    user_id: Optional[str] = None,
    limit: int = 50,
) -> List[Notification]:
    """Fetches recent notifications for a user or system-wide broadcast notifications."""
    query = select(Notification)
    if user_id:
        query = query.where((Notification.user_id == user_id) | (Notification.user_id == None))
    query = query.order_by(desc(Notification.created_at)).limit(limit)
    res = await db.execute(query)
    return list(res.scalars().all())


async def mark_notification_as_read(
    db: AsyncSession,
    notification_id: str,
    user_id: Optional[str] = None,
) -> bool:
    """Marks a single notification as read."""
    query = select(Notification).where(Notification.id == notification_id)
    if user_id:
        query = query.where((Notification.user_id == user_id) | (Notification.user_id == None))
    res = await db.execute(query)
    notification = res.scalar_one_or_none()
    if not notification:
        return False
    notification.is_read = True
    await db.commit()
    return True


async def mark_all_notifications_as_read(
    db: AsyncSession,
    user_id: Optional[str] = None,
) -> int:
    """Marks all unread notifications as read for a user."""
    query = select(Notification).where(Notification.is_read == False)
    if user_id:
        query = query.where((Notification.user_id == user_id) | (Notification.user_id == None))
    res = await db.execute(query)
    notifications = res.scalars().all()
    count = len(notifications)
    for n in notifications:
        n.is_read = True
    await db.commit()
    return count

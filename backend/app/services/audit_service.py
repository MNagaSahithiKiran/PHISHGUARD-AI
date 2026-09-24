from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.logging import logger
from app.models.audit import AuditLog


async def log_audit_event(
    db: AsyncSession,
    event_type: str,
    action: str,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    status: str = "success",
    client_ip: Optional[str] = None,
    details: Optional[str] = None,
) -> Optional[AuditLog]:
    """
    Records an immutable audit event in the database.
    Catches errors gracefully to prevent business flow interruption.
    """
    try:
        log_entry = AuditLog(
            user_id=user_id,
            user_email=user_email,
            event_type=event_type,
            action=action,
            status=status,
            client_ip=client_ip,
            details=details,
        )
        db.add(log_entry)
        await db.commit()
        return log_entry
    except Exception as e:
        logger.error(f"Failed to record audit log: {e}")
        await db.rollback()
        return None

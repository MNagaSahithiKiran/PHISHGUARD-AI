import os
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.models.audit import AuditLog


class RetentionCleanupService:
    """Enterprise Data Retention Policy Service.
    Safely purges expired screenshots and historical audit records according to regulatory retention windows.
    """

    def __init__(
        self,
        screenshot_dir: str = "storage/screenshots",
        screenshot_retention_days: int = settings.RETENTION_DAYS_SCREENSHOTS,
        audit_retention_days: int = settings.RETENTION_DAYS_AUDIT_LOGS,
    ):
        self.screenshot_dir = Path(screenshot_dir)
        self.screenshot_retention_seconds = screenshot_retention_days * 86400
        self.audit_retention_days = audit_retention_days

    async def purge_expired_data(self, session: AsyncSession) -> Dict[str, Any]:
        """Executes data retention purge and returns an audit count."""
        now = time.time()
        screenshot_cutoff = now - self.screenshot_retention_seconds
        deleted_screenshots = 0

        # 1. Prune expired screenshot files on disk
        if self.screenshot_dir.exists():
            for file_path in self.screenshot_dir.glob("*.png"):
                try:
                    mtime = file_path.stat().st_mtime
                    if mtime < screenshot_cutoff:
                        file_path.unlink()
                        deleted_screenshots += 1
                except Exception as e:
                    logger.warning(f"Could not purge screenshot {file_path}: {e}")

        # 2. Prune expired audit logs
        audit_cutoff_dt = datetime.utcnow() - timedelta(days=self.audit_retention_days)
        deleted_audits = 0
        try:
            stmt = delete(AuditLog).where(AuditLog.created_at < audit_cutoff_dt)
            result = await session.execute(stmt)
            await session.commit()
            deleted_audits = result.rowcount or 0
        except Exception as e:
            logger.warning(f"Could not purge expired audit logs: {e}")
            await session.rollback()

        logger.info(
            f"Retention cleanup complete: {deleted_screenshots} screenshot(s) purged, "
            f"{deleted_audits} audit log record(s) older than {self.audit_retention_days} days purged."
        )

        return {
            "deleted_screenshots": deleted_screenshots,
            "deleted_audit_records": deleted_audits,
            "screenshot_retention_days": settings.RETENTION_DAYS_SCREENSHOTS,
            "audit_retention_days": settings.RETENTION_DAYS_AUDIT_LOGS,
            "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


retention_service = RetentionCleanupService()

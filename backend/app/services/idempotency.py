import hashlib
import time
from urllib.parse import urlparse
from typing import Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.models.scan import Scan, ScanResult


def normalize_target_url(raw_url: str) -> str:
    """Normalizes URL for consistent hashing and deduplication."""
    url = raw_url.strip()
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/') or '/'
        query = parsed.query
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized = f"{normalized}?{query}"
        return normalized
    except Exception:
        return url.lower().rstrip('/')


def compute_url_fingerprint(normalized_url: str) -> str:
    """Computes a SHA-256 fingerprint for idempotency tracking."""
    return hashlib.sha256(normalized_url.encode('utf-8')).hexdigest()


class IdempotencyManager:
    """Prevents duplicate scan requests within a configurable time window."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds

    async def find_recent_scan(
        self,
        session: AsyncSession,
        url: str,
        user_id: Optional[str] = None
    ) -> Optional[Scan]:
        """Checks if a matching scan exists within the idempotency window.
        Returns the existing Scan if active/completed within the window, else None.
        """
        norm_url = normalize_target_url(url)
        cutoff_time = time.time() - self.window_seconds

        query = (
            select(Scan)
            .where(Scan.url == norm_url)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )

        res = await session.execute(query)
        recent_scan = res.scalar_one_or_none()

        if recent_scan:
            # Check if scan is within idempotency window
            scan_time = recent_scan.created_at.timestamp() if recent_scan.created_at else 0
            if scan_time > cutoff_time:
                logger.info(
                    f"Idempotency hit: Target '{norm_url}' already scanned within {self.window_seconds}s "
                    f"(Scan ID: {recent_scan.id}, Status: {recent_scan.status})"
                )
                return recent_scan

        return None


idempotency_manager = IdempotencyManager(window_seconds=settings.IDEMPOTENCY_WINDOW_SECONDS)

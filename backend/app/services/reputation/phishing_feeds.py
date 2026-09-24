import time
import os
from typing import Dict, Any, Optional, Set
from pathlib import Path

from app.core.config import settings
from app.core.logging import logger
from app.services.reputation.base import ReputationProvider
from app.services.reputation.schemas import ProviderResult, ReputationStatus


class PhishingFeedProvider(ReputationProvider):
    name: str = "phishing_feeds"
    evidence_type: str = "threat_feed"

    def __init__(self):
        self.feed_url: Optional[str] = getattr(settings, "OPEN_PHISH_FEED_URL", None)
        # Check for local feed cache file if present in data directory
        data_feed_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "feeds" / "active_phishing_feed.txt"
        self.local_feed_file = data_feed_path if data_feed_path.exists() else None
        self._cached_urls: Optional[Set[str]] = None
        self._load_local_feed()

    def _load_local_feed(self) -> None:
        if self.local_feed_file and self.local_feed_file.exists():
            try:
                with open(self.local_feed_file, "r", encoding="utf-8") as f:
                    self._cached_urls = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
            except Exception as e:
                logger.warning(f"Failed to load local phishing feed: {e}")
                self._cached_urls = None

    def is_configured(self) -> bool:
        return bool(self.feed_url or (self._cached_urls is not None and len(self._cached_urls) > 0))

    async def query(self, url: str, domain: str) -> ProviderResult:
        start_time = time.perf_counter()

        if not self.is_configured():
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.NOT_CONFIGURED,
                summary="Phishing feed source is not configured.",
                is_threat=None,
                confidence=None,
                details={
                    "configured": False,
                    "reason": "No active OPEN_PHISH_FEED_URL or local feed list provided",
                    "note": "Unconfigured feeds do not declare a URL clean."
                },
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        # Check local loaded feed
        cleaned_url = url.strip().lower().rstrip("/")
        cleaned_domain = domain.strip().lower()

        is_match = False
        matched_entry = None

        if self._cached_urls:
            if cleaned_url in self._cached_urls:
                is_match = True
                matched_entry = cleaned_url
            else:
                for entry in self._cached_urls:
                    if entry in cleaned_url or (len(entry) > 4 and entry == cleaned_domain):
                        is_match = True
                        matched_entry = entry
                        break

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if is_match:
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.THREAT_MATCH,
                summary=f"URL matched entry in active phishing feed ({matched_entry}).",
                is_threat=True,
                confidence=0.98,
                details={"feed_entry": matched_entry, "cached_feed_size": len(self._cached_urls or [])},
                query=url,
                latency_ms=latency_ms,
            )
        else:
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.SAFE,
                summary="URL is not present in active phishing threat feeds.",
                is_threat=False,
                confidence=0.85,
                details={"cached_feed_size": len(self._cached_urls or [])},
                query=url,
                latency_ms=latency_ms,
            )

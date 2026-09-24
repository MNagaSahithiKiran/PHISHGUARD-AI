import asyncio
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.core.logging import logger
from app.services.reputation.schemas import (
    ProviderResult,
    ReputationStatus,
    ReputationEvidenceItem,
    ExternalReputationSummary,
)
from app.services.reputation.base import ReputationProvider
from app.services.reputation.google_search import GoogleSearchProvider
from app.services.reputation.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.reputation.virustotal import VirusTotalProvider
from app.services.reputation.phishing_feeds import PhishingFeedProvider


class ReputationService:
    _instance: Optional["ReputationService"] = None

    def __init__(self):
        self.providers: Dict[str, ReputationProvider] = {
            "google_search": GoogleSearchProvider(),
            "google_safe_browsing": GoogleSafeBrowsingProvider(),
            "virustotal": VirusTotalProvider(),
            "phishing_feeds": PhishingFeedProvider(),
        }

    @classmethod
    def get_instance(cls) -> "ReputationService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def check_reputation(self, url: str, domain: str) -> ExternalReputationSummary:
        """
        Executes parallel threat intelligence lookups across all configured providers.
        Guarantees that unconfigured providers report NOT_CONFIGURED without throwing errors
        or generating fake fallback claims.
        """
        start_time = time.perf_counter()

        tasks = []
        provider_keys = list(self.providers.keys())

        for key in provider_keys:
            provider = self.providers[key]
            tasks.append(provider.query(url=url, domain=domain))

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        provider_results: Dict[str, ProviderResult] = {}
        evidence_ledger: List[ReputationEvidenceItem] = []
        threat_matches = 0
        providers_configured = 0

        for key, res in zip(provider_keys, results_list):
            provider = self.providers[key]
            if isinstance(res, Exception):
                logger.error(f"Reputation provider {key} raised uncaught exception: {res}")
                pr = ProviderResult(
                    provider_name=key,
                    status=ReputationStatus.ERROR,
                    summary=f"Internal error executing {key}: {str(res)}",
                    is_threat=None,
                    confidence=None,
                    details={"error": str(res)},
                    query=url,
                )
            else:
                pr = res

            provider_results[key] = pr
            if pr.status != ReputationStatus.NOT_CONFIGURED:
                providers_configured += 1

            if pr.status == ReputationStatus.THREAT_MATCH:
                threat_matches += 1

            evidence_item = provider.create_evidence_item(pr)
            evidence_ledger.append(evidence_item)

        # Derive overall reputation status
        if threat_matches > 0:
            overall_status = "THREAT_DETECTED"
        elif providers_configured == 0:
            overall_status = "NO_REPUTATION_DATA"
        elif all(
            pr.status in (ReputationStatus.SAFE, ReputationStatus.CONFIRMED_RESULT, ReputationStatus.NOT_CONFIGURED)
            for pr in provider_results.values()
        ):
            overall_status = "CLEAN"
        else:
            overall_status = "PARTIAL"

        return ExternalReputationSummary(
            overall_status=overall_status,
            threat_matches=threat_matches,
            providers_queried=len(provider_keys),
            providers_configured=providers_configured,
            evidence_ledger=evidence_ledger,
            provider_results=provider_results,
        )

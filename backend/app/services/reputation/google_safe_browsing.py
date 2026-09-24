import time
import httpx
from typing import Dict, Any, Optional

from app.core.config import settings
from app.core.logging import logger
from app.services.reputation.base import ReputationProvider
from app.services.reputation.schemas import ProviderResult, ReputationStatus


class GoogleSafeBrowsingProvider(ReputationProvider):
    name: str = "google_safe_browsing"
    evidence_type: str = "threat_lookup"

    def __init__(self):
        self.api_key: Optional[str] = getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def query(self, url: str, domain: str) -> ProviderResult:
        start_time = time.perf_counter()

        if not self.is_configured():
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.NOT_CONFIGURED,
                summary="Google Safe Browsing API key is not configured.",
                is_threat=None,
                confidence=None,
                details={
                    "configured": False,
                    "reason": "Missing GOOGLE_SAFE_BROWSING_API_KEY in environment",
                    "note": "Unconfigured lookup cannot declare a URL safe or malicious."
                },
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "phishguard-ai",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(api_url, json=payload)
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_types = [m.get("threatType") for m in matches]
                        return ProviderResult(
                            provider_name=self.name,
                            status=ReputationStatus.THREAT_MATCH,
                            summary=f"Google Safe Browsing detected threat: {', '.join(threat_types)}",
                            is_threat=True,
                            confidence=0.99,
                            details={"matches": matches, "threat_types": threat_types},
                            query=url,
                            latency_ms=latency_ms,
                            raw_response=data,
                        )
                    else:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ReputationStatus.SAFE,
                            summary="No threat matches found in Google Safe Browsing database.",
                            is_threat=False,
                            confidence=0.95,
                            details={"matches_count": 0},
                            query=url,
                            latency_ms=latency_ms,
                            raw_response=data,
                        )
                elif resp.status_code == 429:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.RATE_LIMITED,
                        summary="Google Safe Browsing rate limit exceeded.",
                        is_threat=None,
                        confidence=None,
                        details={"http_status": 429},
                        query=url,
                        latency_ms=latency_ms,
                    )
                else:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.ERROR,
                        summary=f"Google Safe Browsing API returned HTTP {resp.status_code}.",
                        is_threat=None,
                        confidence=None,
                        details={"http_status": resp.status_code, "body": resp.text[:200]},
                        query=url,
                        latency_ms=latency_ms,
                    )

        except httpx.TimeoutException:
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.UNAVAILABLE,
                summary="Google Safe Browsing API timed out after 5.0s.",
                is_threat=None,
                confidence=None,
                details={"error": "timeout"},
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )
        except Exception as e:
            logger.error(f"GoogleSafeBrowsingProvider error: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.ERROR,
                summary=f"Google Safe Browsing lookup failed: {str(e)}",
                is_threat=None,
                confidence=None,
                details={"error": str(e)},
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

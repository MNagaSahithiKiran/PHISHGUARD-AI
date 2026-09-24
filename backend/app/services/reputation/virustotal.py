import time
import base64
import httpx
from typing import Dict, Any, Optional

from app.core.config import settings
from app.core.logging import logger
from app.services.reputation.base import ReputationProvider
from app.services.reputation.schemas import ProviderResult, ReputationStatus


class VirusTotalProvider(ReputationProvider):
    name: str = "virustotal"
    evidence_type: str = "antivirus_scan"

    def __init__(self):
        self.api_key: Optional[str] = getattr(settings, "VIRUSTOTAL_API_KEY", None)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _url_to_vt_id(url: str) -> str:
        """VirusTotal v3 URL ID is base64url encoded without padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def query(self, url: str, domain: str) -> ProviderResult:
        start_time = time.perf_counter()

        if not self.is_configured():
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.NOT_CONFIGURED,
                summary="VirusTotal API key is not configured.",
                is_threat=None,
                confidence=None,
                details={
                    "configured": False,
                    "reason": "Missing VIRUSTOTAL_API_KEY in environment",
                    "note": "Unconfigured antivirus scan cannot declare a URL safe or malicious."
                },
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        url_id = self._url_to_vt_id(url)
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(api_url, headers=headers)
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    if malicious > 0:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ReputationStatus.THREAT_MATCH,
                            summary=f"VirusTotal detected {malicious} engine flags ({malicious}/{total}).",
                            is_threat=True,
                            confidence=min(1.0, 0.7 + (malicious / max(1, total)) * 0.3),
                            details={"stats": stats, "total_engines": total},
                            query=url,
                            latency_ms=latency_ms,
                            raw_response=stats,
                        )
                    else:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ReputationStatus.SAFE,
                            summary=f"Clean reputation on VirusTotal: 0/{total} engines detected threats.",
                            is_threat=False,
                            confidence=0.9,
                            details={"stats": stats, "total_engines": total},
                            query=url,
                            latency_ms=latency_ms,
                            raw_response=stats,
                        )

                elif resp.status_code == 404:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.NO_RESULT,
                        summary="URL has not been previously analyzed on VirusTotal.",
                        is_threat=None,
                        confidence=0.5,
                        details={"http_status": 404, "note": "Unseen URL on VirusTotal"},
                        query=url,
                        latency_ms=latency_ms,
                    )
                elif resp.status_code == 429:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.RATE_LIMITED,
                        summary="VirusTotal API rate limit reached.",
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
                        summary=f"VirusTotal API returned HTTP {resp.status_code}.",
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
                summary="VirusTotal API timed out after 5.0s.",
                is_threat=None,
                confidence=None,
                details={"error": "timeout"},
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )
        except Exception as e:
            logger.error(f"VirusTotalProvider error: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.ERROR,
                summary=f"VirusTotal lookup failed: {str(e)}",
                is_threat=None,
                confidence=None,
                details={"error": str(e)},
                query=url,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

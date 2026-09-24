import time
import httpx
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.core.config import settings
from app.core.logging import logger
from app.services.reputation.base import ReputationProvider
from app.services.reputation.schemas import ProviderResult, ReputationStatus


class GoogleSearchProvider(ReputationProvider):
    name: str = "google_search"
    evidence_type: str = "search_index"

    def __init__(self):
        self.api_key: Optional[str] = getattr(settings, "GOOGLE_SEARCH_API_KEY", None)
        self.engine_id: Optional[str] = getattr(settings, "GOOGLE_SEARCH_ENGINE_ID", None)

    def is_configured(self) -> bool:
        return bool(self.api_key and self.engine_id)

    async def query(self, url: str, domain: str) -> ProviderResult:
        start_time = time.perf_counter()
        query_str = f"site:{domain}"

        if not self.is_configured():
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.NOT_CONFIGURED,
                summary="Google Search API key or Search Engine ID is not configured.",
                is_threat=None,
                confidence=None,
                details={
                    "configured": False,
                    "reason": "Missing GOOGLE_SEARCH_API_KEY or GOOGLE_SEARCH_ENGINE_ID",
                    "note": "Unconfigured search provider does not indicate safety or malice."
                },
                query=query_str,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        api_url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": self.api_key,
            "cx": self.engine_id,
            "q": query_str,
            "num": 3,
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(api_url, params=params)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    total_results = int(data.get("searchInformation", {}).get("totalResults", 0))

                    if not items or total_results == 0:
                        return ProviderResult(
                            provider_name=self.name,
                            status=ReputationStatus.NO_RESULT,
                            summary="No matching Google Search result was returned by the configured search provider for this query at this time.",
                            is_threat=None,
                            confidence=0.5,
                            details={
                                "total_results": 0,
                                "items_count": 0,
                                "interpretation": "No matching Google Search result was returned by the configured search provider for this query at this time. This is an objective query outcome and not an assertion of malice or indexing status.",
                            },
                            query=query_str,
                            latency_ms=latency_ms,
                            raw_response={"searchInformation": data.get("searchInformation", {})},
                        )

                    top_results = []
                    for item in items[:3]:
                        top_results.append({
                            "title": item.get("title"),
                            "link": item.get("link"),
                            "snippet": item.get("snippet"),
                        })

                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.CONFIRMED_RESULT,
                        summary=f"Found {total_results} matching search results via Google Custom Search API.",
                        is_threat=False,
                        confidence=0.9,
                        details={
                            "total_results": total_results,
                            "results": top_results,
                        },
                        query=query_str,
                        latency_ms=latency_ms,
                        raw_response={"searchInformation": data.get("searchInformation", {})},
                    )

                elif resp.status_code == 429:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.RATE_LIMITED,
                        summary="Google Custom Search API rate limit exceeded.",
                        is_threat=None,
                        confidence=None,
                        details={"http_status": 429},
                        query=query_str,
                        latency_ms=latency_ms,
                    )
                else:
                    return ProviderResult(
                        provider_name=self.name,
                        status=ReputationStatus.ERROR,
                        summary=f"Google Custom Search API returned HTTP {resp.status_code}.",
                        is_threat=None,
                        confidence=None,
                        details={"http_status": resp.status_code, "body": resp.text[:200]},
                        query=query_str,
                        latency_ms=latency_ms,
                    )

        except httpx.TimeoutException:
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.UNAVAILABLE,
                summary="Google Custom Search API timed out after 5.0s.",
                is_threat=None,
                confidence=None,
                details={"error": "timeout"},
                query=query_str,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )
        except Exception as e:
            logger.error(f"GoogleSearchProvider error: {e}")
            return ProviderResult(
                provider_name=self.name,
                status=ReputationStatus.ERROR,
                summary=f"Google Search request failed: {str(e)}",
                is_threat=None,
                confidence=None,
                details={"error": str(e)},
                query=query_str,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

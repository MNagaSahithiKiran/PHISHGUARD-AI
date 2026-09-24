"""
PhishGuard AI - Safe Controlled HTTP Analyzer.
Executes HTTP intake with strict timeouts, stream size caps, manual per-hop
redirect interception, and SSRF verification on every destination.
"""

import time
from typing import Dict, Any, List
import httpx
from urllib.parse import urljoin
from app.analyzers.safety.ssrf_guard import validate_url_safety, SSRFSecurityException
from app.analyzers.safety.redirect_guard import RedirectGuard
from app.analyzers.safety.fetch_policy import (
    CONNECT_TIMEOUT_SEC,
    READ_TIMEOUT_SEC,
    TOTAL_TIMEOUT_SEC,
    MAX_RESPONSE_BYTES,
    MAX_REDIRECTS,
    USER_AGENT,
)
from app.core.logging import logger


class SafeHttpAnalyzer:
    @staticmethod
    async def fetch_url(target_url: str) -> Dict[str, Any]:
        """
        Executes controlled HTTP fetch:
        - Re-evaluates each redirect hop through SSRF guard.
        - Streams response with size cap to avoid memory exhaustion / archive bombs.
        - Never transmits user cookies, sessions, or credentials.
        """
        initial_safe = validate_url_safety(target_url)
        current_url = initial_safe["url"]

        redirect_guard = RedirectGuard(max_redirects=MAX_REDIRECTS)
        redirect_guard.visited_urls.append(current_url)

        hops: List[Dict[str, Any]] = []
        final_response_text = ""
        final_headers: Dict[str, str] = {}
        status_code = 0
        content_type = ""
        total_time_ms = 0.0

        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        timeout = httpx.Timeout(
            TOTAL_TIMEOUT_SEC,
            connect=CONNECT_TIMEOUT_SEC,
            read=READ_TIMEOUT_SEC,
            write=5.0
        )

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=False) as client:
            step = 0
            while step <= MAX_REDIRECTS:
                step += 1
                hop_start = time.time()
                try:
                    # Stream response to strictly enforce byte limit
                    async with client.stream("GET", current_url, headers=headers) as response:
                        hop_duration = round((time.time() - hop_start) * 1000, 2)
                        status_code = response.status_code
                        final_headers = dict(response.headers)
                        content_type = response.headers.get("content-type", "")

                        # Record redirect if status is 3xx
                        if 300 <= status_code < 400 and "location" in response.headers:
                            loc = response.headers["location"]
                            next_target_info = redirect_guard.validate_next_hop(current_url, loc)
                            next_url = next_target_info["url"]

                            hops.append({
                                "hop_number": len(hops) + 1,
                                "source_url": current_url,
                                "target_url": next_url,
                                "status_code": status_code,
                                "response_time_ms": hop_duration,
                            })
                            current_url = next_url
                            continue

                        # Terminal response reached
                        chunks = []
                        total_bytes = 0
                        async for chunk in response.aiter_bytes():
                            total_bytes += len(chunk)
                            if total_bytes > MAX_RESPONSE_BYTES:
                                logger.warning(f"Response exceeded size cap ({MAX_RESPONSE_BYTES} bytes)")
                                break
                            chunks.append(chunk)

                        raw_bytes = b"".join(chunks)
                        # Decode HTML safely
                        final_response_text = raw_bytes.decode("utf-8", errors="replace")
                        total_time_ms += hop_duration
                        break

                except (SSRFSecurityException, httpx.TimeoutException):
                    raise
                except Exception as e:
                    logger.warning(f"Fetch failure on {current_url}: {e}")
                    status_code = status_code or 0
                    break

        return {
            "initial_url": target_url,
            "final_url": current_url,
            "status_code": status_code,
            "content_type": content_type,
            "response_size_bytes": len(final_response_text.encode("utf-8")),
            "response_time_ms": total_time_ms,
            "headers": final_headers,
            "server_header": final_headers.get("server"),
            "hops": hops,
            "html": final_response_text,
        }


class SafeFetchResult:
    def __init__(
        self,
        final_url: str,
        status_code: int,
        headers: Dict[str, str],
        html_content: str,
        content_length: int,
        response_time_ms: float,
        redirect_chain: List[Dict[str, Any]],
        ip_address: str = None,
        error: str = None,
        truncated: bool = False,
    ):
        self.final_url = final_url
        self.status_code = status_code
        self.headers = headers
        self.html_content = html_content
        self.content_length = content_length
        self.response_time_ms = response_time_ms
        self.redirect_chain = redirect_chain
        self.ip_address = ip_address
        self.error = error
        self.truncated = truncated


async def safe_http_fetch(target_url: str) -> SafeFetchResult:
    """
    Adapter invoking SafeHttpAnalyzer.fetch_url and returning a typed SafeFetchResult.
    """
    try:
        raw_res = await SafeHttpAnalyzer.fetch_url(target_url)
        return SafeFetchResult(
            final_url=raw_res.get("final_url", target_url),
            status_code=raw_res.get("status_code", 0),
            headers=raw_res.get("headers", {}),
            html_content=raw_res.get("html", ""),
            content_length=raw_res.get("response_size_bytes", 0),
            response_time_ms=raw_res.get("response_time_ms", 0.0),
            redirect_chain=raw_res.get("hops", []),
            error=None,
        )
    except SSRFSecurityException as ssrf_err:
        return SafeFetchResult(
            final_url=target_url,
            status_code=0,
            headers={},
            html_content="",
            content_length=0,
            response_time_ms=0.0,
            redirect_chain=[],
            error=str(ssrf_err.detail if hasattr(ssrf_err, 'detail') else ssrf_err),
        )
    except Exception as e:
        return SafeFetchResult(
            final_url=target_url,
            status_code=0,
            headers={},
            html_content="",
            content_length=0,
            response_time_ms=0.0,
            redirect_chain=[],
            error=str(e),
        )


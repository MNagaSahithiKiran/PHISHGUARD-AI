"""
PhishGuard AI - Redirect Guard & Chain Safety Validator.
Re-evaluates every redirect target through SSRF validation to prevent
multi-hop evasion (e.g., public URL redirecting to 169.254.169.254).
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from app.analyzers.safety.ssrf_guard import validate_url_safety, SSRFSecurityException
from app.analyzers.safety.fetch_policy import MAX_REDIRECTS
from app.core.logging import logger


class RedirectGuard:
    def __init__(self, max_redirects: int = MAX_REDIRECTS):
        self.max_redirects = max_redirects
        self.visited_urls: List[str] = []

    def validate_next_hop(self, current_url: str, location_header: str) -> Dict[str, Any]:
        """
        Resolves relative redirect targets against the current URL,
        evaluates SSRF barriers on the target, and checks for redirect loops.
        """
        if len(self.visited_urls) >= self.max_redirects:
            logger.warning(f"Redirect limit exceeded ({self.max_redirects} hops)")
            raise SSRFSecurityException("Excessive redirects detected.")

        # Resolve relative redirects
        target_url = urljoin(current_url, location_header.strip())

        # Check for infinite loops
        if target_url in self.visited_urls:
            logger.warning(f"Redirect loop detected targeting: {target_url}")
            raise SSRFSecurityException("Redirect loop detected.")

        # Rigorous SSRF check on target destination
        validated_info = validate_url_safety(target_url)

        self.visited_urls.append(target_url)
        return validated_info

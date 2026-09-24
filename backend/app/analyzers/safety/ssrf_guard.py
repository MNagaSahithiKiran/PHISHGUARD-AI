"""
PhishGuard AI - SSRF Guard Engine.
Validates protocol schemes and resolves DNS to strictly block internal VPC, loopback,
private subnets, and cloud metadata before any network sockets are created.
"""

import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException, status
from app.analyzers.safety.ip_validator import is_ip_restricted
from app.analyzers.safety.fetch_policy import (
    ALLOWED_SCHEMES,
    DISALLOWED_SCHEMES,
    RESTRICTED_HOSTNAMES,
)
from app.core.logging import logger


class SSRFSecurityException(HTTPException):
    def __init__(self, message: str = "Analysis blocked for security reasons."):
        # Sanitized user-facing message prevents reconnaissance of internal IPs
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


def validate_url_safety(raw_url: str) -> dict:
    """
    Rigorously verifies target URL safety:
    1. Rejects dangerous and unsupported URI schemes.
    2. Enforces valid hostname.
    3. Blocks known local names (localhost, metadata).
    4. Evaluates direct IP hostnames against restricted subnets.
    5. Resolves DNS records and inspects all resolved IPv4 & IPv6 addresses.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SSRFSecurityException("Analysis blocked for security reasons.")

    url = raw_url.strip()
    if len(url) > 2048:
        raise SSRFSecurityException("URL exceeds maximum length.")

    # Check scheme
    if ":" in url:
        potential_scheme = url.split(":", 1)[0].lower()
        if potential_scheme in DISALLOWED_SCHEMES or potential_scheme not in ALLOWED_SCHEMES:
            logger.warning(f"SSRF Alert: Blocked disallowed scheme '{potential_scheme}' for URL: {url[:50]}")
            raise SSRFSecurityException("Analysis blocked for security reasons.")
    else:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        raise SSRFSecurityException("Analysis blocked for security reasons.")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFSecurityException("Analysis blocked for security reasons.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise SSRFSecurityException("Analysis blocked for security reasons.")

    if hostname in RESTRICTED_HOSTNAMES:
        logger.warning(f"SSRF Alert: Blocked restricted hostname '{hostname}'")
        raise SSRFSecurityException("Analysis blocked for security reasons.")

    # Check if host is direct IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_restricted(str(ip_obj)):
            logger.warning(f"SSRF Alert: Blocked restricted IP hostname '{hostname}'")
            raise SSRFSecurityException("Analysis blocked for security reasons.")
        resolved_ips = [str(ip_obj)]
    except ValueError:
        # Resolve via DNS to detect SSRF & DNS rebinding
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = list(set(item[4][0] for item in addr_info))
            for ip in resolved_ips:
                if is_ip_restricted(ip):
                    logger.warning(f"SSRF Alert: Domain '{hostname}' resolved to restricted IP '{ip}'")
                    raise SSRFSecurityException("Analysis blocked for security reasons.")
        except socket.gaierror:
            # Unresolvable domains can be analyzed purely lexically or flagged
            resolved_ips = []
        except SSRFSecurityException:
            raise
        except Exception as e:
            logger.warning(f"DNS resolution check error for '{hostname}': {e}")
            resolved_ips = []

    return {
        "url": parsed.geturl(),
        "scheme": scheme,
        "hostname": hostname,
        "port": parsed.port or (443 if scheme == "https" else 80),
        "path": parsed.path or "/",
        "query": parsed.query,
        "resolved_ips": resolved_ips,
    }


class SSRFGuard:
    @staticmethod
    def validate_target_url(raw_url: str) -> dict:
        return validate_url_safety(raw_url)


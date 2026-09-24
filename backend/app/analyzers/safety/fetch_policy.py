"""
PhishGuard AI - Fetch Policy & Safe Resource Constraints.
Defines security timeouts, stream caps, and protocol restrictions.
"""

from typing import Set

CONNECT_TIMEOUT_SEC: float = 5.0
READ_TIMEOUT_SEC: float = 8.0
TOTAL_TIMEOUT_SEC: float = 10.0

MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024  # 5 MB stream cap
MAX_REDIRECTS: int = 5

USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuard/1.0"
)

ALLOWED_SCHEMES: Set[str] = {"http", "https"}

DISALLOWED_SCHEMES: Set[str] = {
    "file", "ftp", "javascript", "data", "chrome", "about",
    "gopher", "ldap", "dict", "blob", "filesystem", "ws", "wss"
}

RESTRICTED_HOSTNAMES: Set[str] = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "instance-data",
}


class FetchPolicy:
    MAX_REDIRECTS: int = MAX_REDIRECTS
    MAX_RESPONSE_BYTES: int = MAX_RESPONSE_BYTES
    CONNECT_TIMEOUT_SECONDS: float = CONNECT_TIMEOUT_SEC
    TOTAL_TIMEOUT_SECONDS: float = TOTAL_TIMEOUT_SEC
    USER_AGENT: str = USER_AGENT
    ALLOWED_SCHEMES: Set[str] = ALLOWED_SCHEMES
    DISALLOWED_SCHEMES: Set[str] = DISALLOWED_SCHEMES
    RESTRICTED_HOSTNAMES: Set[str] = RESTRICTED_HOSTNAMES

import hashlib
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import bcrypt
import jwt
import tldextract
from fastapi import HTTPException, status
from app.core.config import settings
from app.core.logging import logger


class SecurityValidationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt with automatic salt generation."""
    if not password:
        raise ValueError("Password cannot be empty")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Securely verifies a password against its bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generates an RFC 7519 compliant JSON Web Token with expiration."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token. Returns payload dict or None if invalid/expired."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub"]}
        )
        return payload
    except jwt.PyJWTError as e:
        logger.warning(f"JWT decode error: {e}")
        return None



def is_ip_private_or_restricted(ip_str: str) -> bool:
    """
    Evaluates whether an IP address belongs to loopback, RFC 1918 private space,
    link-local, cloud metadata, or reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip) in ["169.254.169.254", "0.0.0.0"]
        )
    except ValueError:
        return True


def normalize_url(raw_url: str) -> str:
    """
    Canonical URL Normalization Function.
    Every part of the application must use this single canonical function.
    Deterministic normalization rules:
    1. Trims whitespace.
    2. Enforces scheme presence (defaults https:// if absent).
    3. Lowercases scheme (http or https).
    4. Lowercases hostname and normalizes IDN/punycode.
    5. Strips default ports (:80 for http, :443 for https).
    6. Normalizes path: collapses multiple consecutive slashes (e.g. // -> /),
       defaults empty path to '/'.
    7. Canonically sorts query parameters by key and value (?b=2&a=1 -> ?a=1&b=2).
    8. Documented fragment policy: URL fragments (#anchor) are client-side only
       and never transmitted over HTTP to origin servers; stripped for canonical
       server-side threat scanning.
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        if ":" in url and url.split(":", 1)[0].lower() in ["http", "https"]:
            pass
        else:
            url = "https://" + url

    try:
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        import re
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ["http", "https"]:
            scheme = "https"

        hostname = (parsed.hostname or "").lower()
        # Punycode normalization for internationalized domain names
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except Exception:
            hostname = hostname.lower()

        port = parsed.port
        # Strip default ports
        if port:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = hostname
            else:
                netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        # Path normalization: collapse redundant slashes and default to /
        path = parsed.path or "/"
        path = re.sub(r"/+", "/", path)
        if not path.startswith("/"):
            path = "/" + path

        # Query normalization: sort parameters canonically
        query = ""
        if parsed.query:
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            pairs_sorted = sorted(pairs, key=lambda x: (x[0], x[1]))
            query = urlencode(pairs_sorted)

        # Fragment is stripped per documented policy
        fragment = ""

        return urlunparse((scheme, netloc, path, "", query, fragment))
    except Exception:
        return url


def validate_and_sanitize_url(raw_url: str) -> dict:
    """
    Performs rigorous URL validation:
    1. Trims whitespace and length checks.
    2. Enforces HTTP or HTTPS protocol only.
    3. Blocks localhost and non-resolvable suspicious constructs.
    4. Performs DNS resolution to prevent Server-Side Request Forgery (SSRF) targeting
       internal VPC / local services.
    5. Extracts structured domain components using tldextract.
    6. Produces canonical normalized_url and canonical_url via normalize_url().
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SecurityValidationError("URL cannot be empty")

    url = raw_url.strip()
    if len(url) > 2048:
        raise SecurityValidationError("URL exceeds maximum permitted length of 2048 characters")

    # Check for scheme presence: e.g. scheme:...
    if ":" in url:
        potential_scheme = url.split(":", 1)[0].lower()
        if potential_scheme not in ["http", "https"]:
            raise SecurityValidationError(
                f"Disallowed protocol '{potential_scheme}'. Only HTTP and HTTPS are permitted."
            )
    else:
        # No scheme specified, prepend https://
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityValidationError(f"Invalid URL structure: {str(e)}")

    if parsed.scheme.lower() not in ["http", "https"]:
        raise SecurityValidationError(f"Disallowed protocol '{parsed.scheme}'. Only HTTP/HTTPS are supported.")

    # Disallow embedded credentials in URL (e.g. https://user:pass@example.com)
    if parsed.username or parsed.password:
        raise SecurityValidationError("Embedded credentials (username/password) in URL are prohibited.")

    # Validate port number if specified
    try:
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            raise SecurityValidationError(f"Invalid URL port number '{port}'. Port must be between 1 and 65535.")
    except ValueError as ve:
        raise SecurityValidationError(f"Invalid URL port: {str(ve)}")

    hostname = parsed.hostname
    if not hostname or hostname == "." or hostname.startswith(".") or hostname.endswith("."):
        raise SecurityValidationError("URL must include a valid hostname.")

    hostname = hostname.lower()

    # Block obvious local names
    if hostname in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
        raise SecurityValidationError("SSRF Protection: Requests to localhost or loopback are strictly forbidden.")

    # Validate hostname structure (must not contain invalid characters or consecutive dots)
    if ".." in hostname or any(c in hostname for c in [" ", "\t", "\\", "/", ":", "@", "?", "#"]):
        raise SecurityValidationError(f"Invalid hostname format '{hostname}'.")

    # Check if hostname itself is directly an IP literal
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        if settings.ENABLE_SSRF_PROTECTION and not settings.ALLOW_PRIVATE_IPS:
            if is_ip_private_or_restricted(str(ip_obj)):
                raise SecurityValidationError(f"SSRF Protection: Access to private/internal IP {hostname} is forbidden.")
    except ValueError:
        is_ip = False

    if not is_ip:
        # Hostname must contain at least one dot separating domain and TLD (e.g. example.com, not bare 'abc')
        if "." not in hostname:
            raise SecurityValidationError(
                f"Invalid hostname '{hostname}'. Hostname must contain a valid domain label and top-level domain."
            )
        # Check domain labels (must not start or end with hyphen)
        labels = hostname.split(".")
        for lbl in labels:
            if not lbl or lbl.startswith("-") or lbl.endswith("-"):
                raise SecurityValidationError(f"Invalid domain label '{lbl}' in hostname '{hostname}'.")

        # Resolve via DNS if SSRF protection is enabled
        if settings.ENABLE_SSRF_PROTECTION and not settings.ALLOW_PRIVATE_IPS:
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                resolved_ips = set(item[4][0] for item in addr_info)
                
                for resolved_ip in resolved_ips:
                    if is_ip_private_or_restricted(resolved_ip):
                        logger.warning(f"SSRF Alert: Domain '{hostname}' resolved to restricted IP: {resolved_ip}")
                        raise SecurityValidationError(
                            f"SSRF Protection: Domain resolves to restricted or private network space ({resolved_ip})."
                        )
            except socket.gaierror:
                logger.info(f"Domain '{hostname}' did not resolve in DNS.")
            except SecurityValidationError:
                raise
            except Exception as e:
                logger.warning(f"Error during SSRF DNS resolution for {hostname}: {str(e)}")

    # Canonical URL Normalization
    normalized_url = normalize_url(url)
    norm_parsed = urlparse(normalized_url)

    # Extract domain components cleanly
    extracted = tldextract.extract(normalized_url)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    if not registered_domain:
        registered_domain = norm_parsed.hostname or hostname

    return {
        "original_url": raw_url,
        "normalized_url": normalized_url,
        "canonical_url": normalized_url,
        "scheme": norm_parsed.scheme.lower(),
        "hostname": norm_parsed.hostname or hostname,
        "domain": registered_domain,
        "subdomain": extracted.subdomain,
        "suffix": extracted.suffix,
        "path": norm_parsed.path or "/",
        "query": norm_parsed.query,
    }


"""
PhishGuard AI - Master URL Feature Extractor.
Extracts 34 deterministic mathematical, structural, and lexical features.
Works consistently for training and real-time inference.
"""

from urllib.parse import urlparse, parse_qs
import ipaddress
import re
from ml.feature_engineering.lexical_features import (
    calculate_shannon_entropy,
    calculate_repeated_char_max,
    calculate_char_ratios,
)
from ml.feature_engineering.domain_features import OfflineDomainProvider

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "tiny.cc"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "security", "update",
    "account", "banking", "wallet", "signin", "support", "auth",
    "password", "recovery", "confirm", "billing", "client", "portal"
}

SUSPICIOUS_BRANDS = {
    "paypal", "apple", "microsoft", "google", "netflix", "amazon",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "metamask", "whatsapp", "telegram", "icloud"
}

domain_provider = OfflineDomainProvider()


def extract_url_feature_vector(url: str) -> dict:
    """
    Transforms a single URL string into a 34-dimensional numerical feature dictionary.
    Deterministic, robust against malformed input, and zero network dependence.
    """
    if not isinstance(url, str):
        url = str(url) if url is not None else ""
    url_clean = url.strip()

    # Prepend scheme if absent for uniform parsing
    u_parsed = url_clean
    if not (url_clean.startswith("http://") or url_clean.startswith("https://") or url_clean.startswith("ftp://")):
        u_parsed = "https://" + url_clean

    try:
        parsed = urlparse(u_parsed)
    except Exception:
        # Fallback if unparseable
        parsed = urlparse("https://malformed.invalid")

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Character counts
    count_dots = url_clean.count(".")
    count_hyphens = url_clean.count("-")
    count_underscores = url_clean.count("_")
    count_slashes = url_clean.count("/")
    count_question = url_clean.count("?")
    count_equals = url_clean.count("=")
    count_ampersand = url_clean.count("&")
    count_percent = url_clean.count("%")
    count_digits = sum(c.isdigit() for c in url_clean)
    count_letters = sum(c.isalpha() for c in url_clean)
    count_special = sum(1 for c in url_clean if not c.isalnum() and c not in ["/", ":", "."])

    # Ratios
    ratio_digits, ratio_specials = calculate_char_ratios(url_clean)

    # IP address check
    has_ip = False
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    # Structural & Domain features
    domain_info = domain_provider.extract_domain_features(url_clean)

    # Token counting
    path_tokens = [t for t in path.split("/") if t]
    path_token_count = len(path_tokens)

    try:
        query_params = parse_qs(query)
        query_param_count = len(query_params)
    except Exception:
        query_param_count = 0

    # Ratios
    hostname_path_ratio = round(len(hostname) / max(1, len(path)), 4)

    # Entropies
    url_entropy = calculate_shannon_entropy(url_clean)
    hostname_entropy = calculate_shannon_entropy(hostname)

    # Repeated characters
    repeated_char_max = calculate_repeated_char_max(url_clean)

    # Keyword and brand matches
    url_lower = url_clean.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    brand_count = sum(1 for b in SUSPICIOUS_BRANDS if b in url_lower)

    # Indicators
    has_shortener = hostname in KNOWN_SHORTENERS
    has_https = 1 if parsed.scheme.lower() == "https" else 0
    has_at = 1 if "@" in url_clean else 0
    has_encoded = 1 if "%" in url_clean else 0

    features = {
        "url_length": len(url_clean),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "count_slashes": count_slashes,
        "count_question_marks": count_question,
        "count_equals": count_equals,
        "count_ampersands": count_ampersand,
        "count_percent": count_percent,
        "count_digits": count_digits,
        "count_letters": count_letters,
        "count_special_chars": count_special,
        "ratio_digits_url": ratio_digits,
        "ratio_special_chars": ratio_specials,
        "count_subdomains": domain_info["subdomain_count"],
        "has_ip_address": int(has_ip),
        "has_at_symbol": has_at,
        "has_shortener": int(has_shortener),
        "has_https": has_https,
        "suspicious_keyword_count": keyword_count,
        "hostname_entropy": hostname_entropy,
        "url_entropy": url_entropy,
        "path_token_count": path_token_count,
        "query_param_count": query_param_count,
        "is_suspicious_tld": domain_info["is_suspicious_tld"],
        "has_punycode": domain_info["has_punycode"],
        "has_encoded_chars": has_encoded,
        "hostname_path_ratio": hostname_path_ratio,
        "repeated_char_max": repeated_char_max,
        "suspicious_brand_token": brand_count,
    }
    return features

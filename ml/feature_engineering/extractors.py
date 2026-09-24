"""
Feature Engineering Extractor Module for PhishGuard AI.
Transforms raw URLs and website metadata into numeric tabular feature vectors
suitable for training Scikit-learn and XGBoost classifiers.
"""

import math
from collections import Counter
from urllib.parse import urlparse
import ipaddress
import re

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at"
}

SUSPICIOUS_KEYWORD_TOKENS = {
    "login", "verify", "account", "banking", "secure", "update",
    "wallet", "signin", "support", "security", "paypal", "apple",
    "microsoft", "recover", "authenticate", "confirm", "billing"
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for lexical randomness measurement."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features_from_url(url: str) -> dict:
    """
    Extracts a dictionary of 18+ numerical and boolean features
    designed for machine learning models.
    """
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    has_ip = False
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    hostname_parts = hostname.split(".")
    subdomain_count = max(0, len(hostname_parts) - 2)

    url_lower = url.lower()
    keyword_match_count = sum(1 for kw in SUSPICIOUS_KEYWORD_TOKENS if kw in url_lower)

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_underscores": url.count("_"),
        "count_slashes": url.count("/"),
        "count_question_marks": url.count("?"),
        "count_equal_signs": url.count("="),
        "count_at_symbols": url.count("@"),
        "count_subdomains": subdomain_count,
        "count_digits": sum(c.isdigit() for c in url),
        "ratio_digits_url": round(sum(c.isdigit() for c in url) / max(1, len(url)), 4),
        "has_ip_address": int(has_ip),
        "has_punycode": int("xn--" in hostname.lower()),
        "has_shortener": int(hostname.lower() in KNOWN_SHORTENERS),
        "has_https": int(parsed.scheme == "https"),
        "suspicious_keyword_count": keyword_match_count,
        "shannon_entropy": round(calculate_entropy(url), 4)
    }

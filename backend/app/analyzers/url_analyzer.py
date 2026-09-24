import math
from collections import Counter
from urllib.parse import urlparse
import ipaddress
import re

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at"
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for lexical randomness measurement."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_url_lexical_features(sanitized_info: dict) -> dict:
    """
    Computes rigorous, deterministic lexical and structural features
    from the URL and its components.
    """
    url = sanitized_info["normalized_url"]
    hostname = sanitized_info["hostname"]
    path = sanitized_info["path"]
    query = sanitized_info["query"]
    subdomain = sanitized_info.get("subdomain", "")
    
    # Check if host is direct IP address
    has_ip = False
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    has_punycode = "xn--" in hostname.lower()
    has_shortener = hostname.lower() in KNOWN_SHORTENERS
    
    parsed = urlparse(url)
    has_port = parsed.port is not None and parsed.port not in [80, 443]

    subdomains_list = [s for s in subdomain.split(".") if s]
    subdomain_count = len(subdomains_list)

    entropy = calculate_entropy(url)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_at": url.count("@"),
        "count_question_marks": url.count("?"),
        "count_equal_signs": url.count("="),
        "count_subdomains": subdomain_count,
        "has_ip_address": has_ip,
        "has_punycode": has_punycode,
        "has_shortener": has_shortener,
        "has_port_in_url": has_port,
        "entropy_score": entropy,
    }
    return features


def detect_heuristic_indicators(features: dict, sanitized_info: dict) -> list[dict]:
    """
    Detects standard security anomalies based on lexical indicators.
    These are transparent rule-based heuristics that will feed into the ensemble ML engine.
    """
    indicators = []

    if features["has_ip_address"]:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "high",
            "rule_id": "LEX_IP_HOSTNAME",
            "description": "Hostname is an IP address instead of a domain name.",
            "details": f"Target hostname {sanitized_info['hostname']} bypasses standard domain name hierarchy."
        })

    if features["has_punycode"]:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "high",
            "rule_id": "LEX_PUNYCODE_HOMOGRAPH",
            "description": "Punycode detected (potential IDN homograph attack).",
            "details": f"Hostname '{sanitized_info['hostname']}' contains encoded internationalized characters."
        })

    if features["count_at"] > 0:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "critical",
            "rule_id": "LEX_AT_SYMBOL_OBFUSCATION",
            "description": "'@' symbol in URL used to obscure destination host.",
            "details": "The '@' character instructs browsers to ignore preceding credentials and load the host after the symbol."
        })

    if features["count_subdomains"] >= 3:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "medium",
            "rule_id": "LEX_EXCESSIVE_SUBDOMAINS",
            "description": f"Excessive subdomains count ({features['count_subdomains']}).",
            "details": "Multiple nested subdomains are frequently used to impersonate established services."
        })

    if features["has_shortener"]:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "medium",
            "rule_id": "LEX_URL_SHORTENER",
            "description": "Known URL shortening service detected.",
            "details": f"Shortener service '{sanitized_info['hostname']}' masks final landing destination."
        })

    if features["entropy_score"] > 4.5:
        indicators.append({
            "indicator_type": "lexical",
            "severity": "low",
            "rule_id": "LEX_HIGH_ENTROPY",
            "description": f"High lexical Shannon entropy score ({features['entropy_score']}).",
            "details": "Indicates random or algorithmically generated string structure (DGA candidate)."
        })

    return indicators

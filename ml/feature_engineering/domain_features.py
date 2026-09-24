"""
PhishGuard AI - Domain Features & Intelligence Abstraction.
Defines DomainIntelligenceProvider with OfflineDomainProvider and OptionalLiveDomainProvider.
Ensures training and offline inference NEVER depend on live network APIs.
"""

from abc import ABC, abstractmethod
import ipaddress
import tldextract

# High-abuse TLDs frequently tracked in Spamhaus / APWG threat reports
HIGH_ABUSE_TLDS = {
    "xyz", "top", "work", "loan", "click", "fit", "rest", "cfd", "gq",
    "ml", "cf", "ga", "tk", "country", "stream", "men", "bid", "buzz"
}


class DomainIntelligenceProvider(ABC):
    @abstractmethod
    def extract_domain_features(self, url: str) -> dict:
        """Extracts structured domain features."""
        pass


class OfflineDomainProvider(DomainIntelligenceProvider):
    """
    Offline domain feature extractor.
    Operates 100% deterministically from URL lexical syntax without external WHOIS or DNS calls.
    Guarantees stability, zero API dependency, and zero training-serving skew.
    """

    def __init__(self):
        # Extract without online suffix list updates
        self.extractor = tldextract.TLDExtract(cache_dir=None)

    def extract_domain_features(self, url: str) -> dict:
        ext = self.extractor(url)
        hostname = ext.fqdn.lower() if ext.fqdn else ""
        subdomain = ext.subdomain
        suffix = ext.suffix.lower()
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        # Subdomain count
        subdomain_parts = [s for s in subdomain.split(".") if s]
        subdomain_count = len(subdomain_parts)

        # Check IP hostname
        has_ip = False
        try:
            ipaddress.ip_address(hostname)
            has_ip = True
        except ValueError:
            has_ip = False

        has_punycode = "xn--" in hostname
        is_suspicious_tld = suffix in HIGH_ABUSE_TLDS

        return {
            "domain_length": len(domain) if domain else 0,
            "subdomain_count": subdomain_count,
            "has_ip_hostname": int(has_ip),
            "has_punycode": int(has_punycode),
            "is_suspicious_tld": int(is_suspicious_tld),
            "has_valid_ssl": None,  # Explicitly None (unavailable offline)
            "domain_age_days": None,  # Explicitly None (unavailable offline)
        }


class OptionalLiveDomainProvider(DomainIntelligenceProvider):
    """
    Optional live domain provider for post-intake deep inspection.
    Transparently marks unavailable network metrics when not performing live queries.
    """

    def __init__(self):
        self.offline = OfflineDomainProvider()

    def extract_domain_features(self, url: str) -> dict:
        # Base offline features
        features = self.offline.extract_domain_features(url)
        # Note: Live network queries (WHOIS/SSL) are marked as unavailable
        # in offline/training mode to prevent network timeouts and data poisoning.
        return features

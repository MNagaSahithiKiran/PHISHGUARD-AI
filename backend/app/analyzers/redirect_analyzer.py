"""
PhishGuard AI - Redirect Chain Analyzer.
Inspects redirect sequences, protocol transitions (HTTP->HTTPS, HTTPS->HTTP),
hostname hops, and excessive redirection indicators.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse
import tldextract


class RedirectAnalyzer:
    @staticmethod
    def analyze_redirect_chain(hops: List[Dict[str, Any]], initial_url: str = "", final_url: str = "") -> Dict[str, Any]:
        """
        Extracts structural and security attributes from the redirection path.
        """
        hop_count = len(hops)
        parsed_init = urlparse(initial_url)
        parsed_final = urlparse(final_url)

        hostnames = [parsed_init.hostname or ""]
        schemes = [parsed_init.scheme.lower()]

        for h in hops:
            tgt = urlparse(h["target_url"])
            if tgt.hostname:
                hostnames.append(tgt.hostname)
            schemes.append(tgt.scheme.lower())

        unique_hosts = list(set(h.lower() for h in hostnames if h))
        
        # Check domain changes via tldextract
        domains = []
        for h in hostnames:
            ext = tldextract.extract(h)
            reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if reg:
                domains.append(reg.lower())
        unique_domains = list(set(domains))

        # Check protocol transitions
        has_downgrade = False
        has_upgrade = False
        for i in range(len(schemes) - 1):
            if schemes[i] == "https" and schemes[i + 1] == "http":
                has_downgrade = True
            elif schemes[i] == "http" and schemes[i + 1] == "https":
                has_upgrade = True

        is_cross_domain = len(unique_domains) > 1

        processed_hops = []
        for h in hops:
            src_p = urlparse(h["source_url"])
            tgt_p = urlparse(h["target_url"])
            processed_hops.append({
                "hop_number": h["hop_number"],
                "source_url": h["source_url"],
                "target_url": h["target_url"],
                "status_code": h["status_code"],
                "hostname_changed": (src_p.hostname or "").lower() != (tgt_p.hostname or "").lower(),
                "protocol_changed": src_p.scheme.lower() != tgt_p.scheme.lower(),
                "response_time_ms": h.get("response_time_ms", 0.0),
            })

        return {
            "total_redirects": hop_count,
            "has_redirects": hop_count > 0,
            "unique_hostnames_count": len(unique_hosts),
            "unique_domains_count": len(unique_domains),
            "is_cross_domain_redirect": is_cross_domain,
            "has_protocol_downgrade": has_downgrade,
            "has_protocol_upgrade": has_upgrade,
            "hops": processed_hops,
        }


class RedirectChainResult:
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.total_hops = data.get("total_redirects", 0)
        self.hops = data.get("hops", [])
        self.protocol_downgrades = 1 if data.get("has_protocol_downgrade") else 0
        self.cross_domain_redirects = 1 if data.get("is_cross_domain_redirect") else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_hops": self.total_hops,
            "hops": self.hops,
            "protocol_downgrades": self.protocol_downgrades,
            "cross_domain_redirects": self.cross_domain_redirects,
            "has_protocol_upgrade": self.data.get("has_protocol_upgrade", False),
            "unique_domains_count": self.data.get("unique_domains_count", 0),
        }


def analyze_redirect_chain(hops: List[Dict[str, Any]], initial_url: str = "", final_url: str = "") -> RedirectChainResult:
    if not initial_url and hops:
        initial_url = hops[0].get("source_url", "")
    if not final_url and hops:
        final_url = hops[-1].get("target_url", "")
    data = RedirectAnalyzer.analyze_redirect_chain(hops, initial_url, final_url)
    return RedirectChainResult(data)

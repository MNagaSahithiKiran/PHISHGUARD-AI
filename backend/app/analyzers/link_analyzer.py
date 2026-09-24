"""
PhishGuard AI - Anchor & Hyperlink Analyzer.
Classifies hyperlinks into internal, external, relative, and null dummy anchors.
Calculates domain dispersion ratios without recursively crawling targets.
"""

from typing import Dict, Any, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


class LinkAnalysisResult:
    def __init__(
        self,
        total_links: int,
        internal_links: int,
        external_links: int,
        null_empty_links: int,
        external_link_ratio: float,
        null_link_ratio: float,
        distinct_external_domains: List[str],
    ):
        self.total_links = total_links
        self.internal_links = internal_links
        self.external_links = external_links
        self.null_empty_links = null_empty_links
        self.external_link_ratio = external_link_ratio
        self.null_link_ratio = null_link_ratio
        self.distinct_external_domains = distinct_external_domains

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_links": self.total_links,
            "internal_links": self.internal_links,
            "external_links": self.external_links,
            "null_empty_links": self.null_empty_links,
            "external_link_ratio": round(self.external_link_ratio, 4),
            "null_link_ratio": round(self.null_link_ratio, 4),
            "distinct_external_domains": self.distinct_external_domains,
        }


def analyze_links(soup: BeautifulSoup, page_url: str) -> LinkAnalysisResult:
    if not soup:
        return LinkAnalysisResult(0, 0, 0, 0, 0.0, 0.0, [])

    parsed_page = urlparse(page_url)
    page_host = (parsed_page.hostname or "").lower()
    page_ext = tldextract.extract(page_host)
    page_domain = f"{page_ext.domain}.{page_ext.suffix}" if page_ext.suffix else page_ext.domain

    anchors = soup.find_all("a")
    total_links = len(anchors)

    internal_links = 0
    external_links = 0
    null_links = 0
    external_domains: List[str] = []

    for a in anchors:
        raw_href = a.get("href")
        if raw_href is None:
            null_links += 1
            continue

        href = str(raw_href).strip()

        # Null / dummy links
        if not href or href in ["#", "#!"] or href.lower().startswith("javascript:"):
            null_links += 1
            continue

        # Check relative
        if href.startswith("/") or not (href.startswith("http://") or href.startswith("https://") or "://" in href):
            internal_links += 1
            continue

        # Full URL
        link_parsed = urlparse(href)
        link_host = (link_parsed.hostname or "").lower()

        if not link_host:
            null_links += 1
            continue

        link_ext = tldextract.extract(link_host)
        link_domain = f"{link_ext.domain}.{link_ext.suffix}" if link_ext.suffix else link_ext.domain

        if link_domain == page_domain:
            internal_links += 1
        else:
            external_links += 1
            if link_domain:
                external_domains.append(link_domain)

    unique_external_domains = sorted(list(set(external_domains)))
    external_ratio = (external_links / total_links) if total_links > 0 else 0.0
    null_ratio = (null_links / total_links) if total_links > 0 else 0.0

    return LinkAnalysisResult(
        total_links=total_links,
        internal_links=internal_links,
        external_links=external_links,
        null_empty_links=null_links,
        external_link_ratio=external_ratio,
        null_link_ratio=null_ratio,
        distinct_external_domains=unique_external_domains[:25],
    )


class LinkAnalyzer:
    @staticmethod
    def analyze_links(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
        res = analyze_links(soup, page_url)
        return {
            "total_links": res.total_links,
            "internal_links": res.internal_links,
            "external_links": res.external_links,
            "null_links": res.null_empty_links,
            "external_link_ratio": res.external_link_ratio,
            "null_link_ratio": res.null_link_ratio,
            "unique_external_domains_count": len(res.distinct_external_domains),
            "external_domains": res.distinct_external_domains,
        }

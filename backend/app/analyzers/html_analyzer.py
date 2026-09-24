"""
PhishGuard AI - Safe HTML Analyzer.
Parses HTML content using BeautifulSoup without executing arbitrary JavaScript
or making network requests for external sub-resources.
"""

from typing import Dict, Any, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def parse_html_safely(html_str: str) -> BeautifulSoup:
    return BeautifulSoup(html_str or "", "html.parser")


def extract_meta_tags(soup: BeautifulSoup) -> Dict[str, str]:
    meta_tags = {}
    if not soup:
        return meta_tags
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv")
        content = m.get("content")
        if name and content:
            meta_tags[str(name).lower()] = str(content)
    return meta_tags


class SafeHtmlAnalyzer:
    @staticmethod
    def parse_html(html_str: str, base_url: str) -> Tuple[Dict[str, Any], BeautifulSoup]:
        """
        Extracts high-level document metadata and returns clean parsed structure.
        """
        if not html_str:
            html_str = ""

        soup = BeautifulSoup(html_str, "html.parser")

        # Document Title
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""

        # Meta tags
        meta_tags = extract_meta_tags(soup)

        # Canonical URL
        canonical_tag = soup.find("link", rel=lambda r: r and "canonical" in r)
        canonical_url = urljoin(base_url, canonical_tag.get("href")) if canonical_tag and canonical_tag.get("href") else None

        # Base tag (Crucial for phishing: <base> can silently reroute form actions)
        base_tag = soup.find("base")
        base_href = base_tag.get("href") if base_tag else None

        # Favicon
        icon_tag = soup.find("link", rel=lambda r: r and any(i in r for i in ["icon", "shortcut icon"]))
        favicon_url = urljoin(base_url, icon_tag.get("href")) if icon_tag and icon_tag.get("href") else None

        # Text extraction
        for s in soup(["script", "style", "noscript", "svg"]):
            s.extract()
        text_content = soup.get_text(separator=" ", strip=True)

        meta_info = {
            "title": title,
            "title_length": len(title),
            "meta_tag_count": len(meta_tags),
            "has_canonical": canonical_url is not None,
            "canonical_url": canonical_url,
            "has_base_tag": base_href is not None,
            "base_href": base_href,
            "has_favicon": favicon_url is not None,
            "favicon_url": favicon_url,
            "text_length": len(text_content),
            "raw_html_length": len(html_str),
        }

        fresh_soup = BeautifulSoup(html_str, "html.parser")
        return meta_info, fresh_soup

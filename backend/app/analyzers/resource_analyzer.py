"""
PhishGuard AI - Resource Analyzer
Safe, passive inspection of external asset references (images, stylesheets, media).
Phishing pages frequently hotlink 100% of their imagery and styles from the legitimate victim organization.
"""

from typing import Any, Dict, List, Set
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


class ResourceAnalysisResult:
    def __init__(
        self,
        total_resources: int,
        external_resources: int,
        external_resource_ratio: float,
        mixed_content_count: int,
        distinct_resource_domains: List[str],
        stylesheet_count: int,
        external_stylesheets: int,
        image_count: int,
        external_images: int,
    ):
        self.total_resources = total_resources
        self.external_resources = external_resources
        self.external_resource_ratio = external_resource_ratio
        self.mixed_content_count = mixed_content_count
        self.distinct_resource_domains = distinct_resource_domains
        self.stylesheet_count = stylesheet_count
        self.external_stylesheets = external_stylesheets
        self.image_count = image_count
        self.external_images = external_images

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_resources": self.total_resources,
            "external_resources": self.external_resources,
            "external_resource_ratio": round(self.external_resource_ratio, 4),
            "mixed_content_count": self.mixed_content_count,
            "distinct_resource_domains": self.distinct_resource_domains,
            "stylesheet_count": self.stylesheet_count,
            "external_stylesheets": self.external_stylesheets,
            "image_count": self.image_count,
            "external_images": self.external_images,
        }


def analyze_resources(soup: BeautifulSoup, base_url: str) -> ResourceAnalysisResult:
    """
    Analyzes embedded resources: stylesheets (<link rel="stylesheet">), images (<img>),
    audio/video (<audio>, <video>, <source>).
    """
    if not soup:
        return ResourceAnalysisResult(0, 0, 0.0, 0, [], 0, 0, 0, 0)

    is_page_https = base_url.lower().startswith("https://")
    base_domain = ""
    try:
        ext = tldextract.extract(base_url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    stylesheet_count = 0
    external_stylesheets = 0
    image_count = 0
    external_images = 0
    mixed_content_count = 0
    external_domains: Set[str] = set()
    total_resources = 0
    external_resources = 0

    # 1. Stylesheets: <link rel="stylesheet" href="...">
    for link in soup.find_all("link"):
        rel = link.get("rel") or []
        if isinstance(rel, list):
            rel_str = " ".join(rel).lower()
        else:
            rel_str = str(rel).lower()

        if "stylesheet" in rel_str:
            href = (link.get("href") or "").strip()
            if href:
                stylesheet_count += 1
                total_resources += 1
                if href.lower().startswith("http://") and is_page_https:
                    mixed_content_count += 1

                try:
                    p = urlparse(href)
                    if p.netloc:
                        pext = tldextract.extract(p.netloc)
                        dom = f"{pext.domain}.{pext.suffix}".lower()
                        if base_domain and dom and dom != base_domain:
                            external_stylesheets += 1
                            external_resources += 1
                            external_domains.add(dom)
                except Exception:
                    pass

    # 2. Images: <img src="...">
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if src:
            image_count += 1
            total_resources += 1
            if src.lower().startswith("http://") and is_page_https:
                mixed_content_count += 1

            if not src.startswith("data:"):
                try:
                    p = urlparse(src)
                    if p.netloc:
                        pext = tldextract.extract(p.netloc)
                        dom = f"{pext.domain}.{pext.suffix}".lower()
                        if base_domain and dom and dom != base_domain:
                            external_images += 1
                            external_resources += 1
                            external_domains.add(dom)
                except Exception:
                    pass

    # 3. Media: <audio>, <video>, <source>
    for media in soup.find_all(["audio", "video", "source"]):
        src = (media.get("src") or "").strip()
        if src and not src.startswith("data:"):
            total_resources += 1
            if src.lower().startswith("http://") and is_page_https:
                mixed_content_count += 1
            try:
                p = urlparse(src)
                if p.netloc:
                    pext = tldextract.extract(p.netloc)
                    dom = f"{pext.domain}.{pext.suffix}".lower()
                    if base_domain and dom and dom != base_domain:
                        external_resources += 1
                        external_domains.add(dom)
            except Exception:
                pass

    ratio = (external_resources / total_resources) if total_resources > 0 else 0.0

    return ResourceAnalysisResult(
        total_resources=total_resources,
        external_resources=external_resources,
        external_resource_ratio=ratio,
        mixed_content_count=mixed_content_count,
        distinct_resource_domains=sorted(list(external_domains))[:30],
        stylesheet_count=stylesheet_count,
        external_stylesheets=external_stylesheets,
        image_count=image_count,
        external_images=external_images,
    )

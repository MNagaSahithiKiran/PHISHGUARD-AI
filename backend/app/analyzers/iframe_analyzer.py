"""
PhishGuard AI - Iframe Analyzer
Safe, passive analysis of iframe elements within parsed HTML.
Never executes or renders iframe contents.
"""

from typing import Any, Dict, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


class IframeAnalysisResult:
    def __init__(
        self,
        total_iframes: int,
        hidden_iframes: int,
        cross_origin_iframes: int,
        sandboxed_iframes: int,
        suspicious_fullpage_iframes: int,
        iframe_sources: List[Dict[str, Any]],
    ):
        self.total_iframes = total_iframes
        self.hidden_iframes = hidden_iframes
        self.cross_origin_iframes = cross_origin_iframes
        self.sandboxed_iframes = sandboxed_iframes
        self.suspicious_fullpage_iframes = suspicious_fullpage_iframes
        self.iframe_sources = iframe_sources

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_iframes": self.total_iframes,
            "hidden_iframes": self.hidden_iframes,
            "cross_origin_iframes": self.cross_origin_iframes,
            "sandboxed_iframes": self.sandboxed_iframes,
            "suspicious_fullpage_iframes": self.suspicious_fullpage_iframes,
            "iframe_sources": self.iframe_sources,
        }


def analyze_iframes(soup: BeautifulSoup, base_url: str) -> IframeAnalysisResult:
    """
    Safely inspects all <iframe> tags in the page DOM.
    
    Checks for:
    - Zero-size or hidden iframes commonly used for drive-by malware / tracking.
    - Fullscreen credential overlays.
    - External cross-origin framing.
    - Presence or absence of sandbox attributes.
    """
    if not soup:
        return IframeAnalysisResult(0, 0, 0, 0, 0, [])

    base_domain = ""
    try:
        ext = tldextract.extract(base_url)
        base_domain = f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    iframes = soup.find_all("iframe")
    total_iframes = len(iframes)
    hidden_iframes = 0
    cross_origin_iframes = 0
    sandboxed_iframes = 0
    suspicious_fullpage = 0
    sources: List[Dict[str, Any]] = []

    for iframe in iframes:
        src = (iframe.get("src") or "").strip()
        width = str(iframe.get("width") or "").strip().lower()
        height = str(iframe.get("height") or "").strip().lower()
        style = str(iframe.get("style") or "").strip().lower().replace(" ", "")
        sandbox = iframe.get("sandbox")

        is_hidden = False
        is_cross_origin = False
        is_sandboxed = sandbox is not None
        is_fullpage = False

        if is_sandboxed:
            sandboxed_iframes += 1

        # Check hidden
        if (
            width in ("0", "0px", "1", "1px")
            or height in ("0", "0px", "1", "1px")
            or "display:none" in style
            or "visibility:hidden" in style
            or "opacity:0" in style
            or iframe.has_attr("hidden")
        ):
            is_hidden = True
            hidden_iframes += 1

        # Check fullpage overlay
        if (
            (width in ("100%", "100vw") and height in ("100%", "100vh"))
            or ("width:100%" in style and "height:100%" in style)
            or ("position:fixed" in style and "top:0" in style and "left:0" in style)
        ):
            is_fullpage = True
            suspicious_fullpage += 1

        # Check cross-origin
        iframe_domain = ""
        if src and not src.startswith("data:") and not src.startswith("about:"):
            try:
                parsed = urlparse(src)
                if parsed.netloc:
                    pext = tldextract.extract(parsed.netloc)
                    iframe_domain = f"{pext.domain}.{pext.suffix}".lower()
                    if base_domain and iframe_domain and iframe_domain != base_domain:
                        is_cross_origin = True
                        cross_origin_iframes += 1
            except Exception:
                pass

        sources.append({
            "src": src[:200] if src else "",
            "domain": iframe_domain,
            "is_hidden": is_hidden,
            "is_cross_origin": is_cross_origin,
            "is_sandboxed": is_sandboxed,
            "is_fullpage": is_fullpage,
        })

    return IframeAnalysisResult(
        total_iframes=total_iframes,
        hidden_iframes=hidden_iframes,
        cross_origin_iframes=cross_origin_iframes,
        sandboxed_iframes=sandboxed_iframes,
        suspicious_fullpage_iframes=suspicious_fullpage,
        iframe_sources=sources[:50],  # Bound length
    )

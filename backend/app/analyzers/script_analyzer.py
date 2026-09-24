"""
PhishGuard AI - Script Metadata & Reference Analyzer.
Parses script tags and external dependency hostnames.
DEFENSIVE REQUIREMENT: NEVER executes JavaScript or evaluates code strings.
"""

from typing import Dict, Any, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


class ScriptAnalysisResult:
    def __init__(
        self,
        total_scripts: int,
        inline_scripts: int,
        external_scripts: int,
        external_script_domains: List[str],
        inline_script_bytes: int,
    ):
        self.total_scripts = total_scripts
        self.inline_scripts = inline_scripts
        self.external_scripts = external_scripts
        self.external_script_domains = external_script_domains
        self.inline_script_bytes = inline_script_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_scripts": self.total_scripts,
            "inline_scripts": self.inline_scripts,
            "external_scripts": self.external_scripts,
            "external_script_domains": self.external_script_domains,
            "inline_script_bytes": self.inline_script_bytes,
        }


def analyze_scripts(soup: BeautifulSoup, page_url: str) -> ScriptAnalysisResult:
    if not soup:
        return ScriptAnalysisResult(0, 0, 0, [], 0)

    scripts = soup.find_all("script")
    inline_count = 0
    external_count = 0
    inline_bytes = 0
    script_domains: List[str] = []

    for s in scripts:
        src = s.get("src")
        if src:
            external_count += 1
            parsed_src = urlparse(src)
            if parsed_src.hostname:
                script_domains.append(parsed_src.hostname.lower())
        else:

            inline_count += 1
            inline_bytes += len(s.get_text().encode("utf-8", errors="replace"))

    unique_script_domains = sorted(list(set(script_domains)))

    return ScriptAnalysisResult(
        total_scripts=len(scripts),
        inline_scripts=inline_count,
        external_scripts=external_count,
        external_script_domains=unique_script_domains[:20],
        inline_script_bytes=inline_bytes,
    )


class ScriptAnalyzer:
    @staticmethod
    def analyze_scripts(soup: BeautifulSoup, page_url: str) -> Dict[str, Any]:
        res = analyze_scripts(soup, page_url)
        return {
            "total_scripts": res.total_scripts,
            "inline_script_count": res.inline_scripts,
            "external_script_count": res.external_scripts,
            "inline_script_bytes": res.inline_script_bytes,
            "unique_script_domains_count": len(res.external_script_domains),
            "script_domains": res.external_script_domains,
        }

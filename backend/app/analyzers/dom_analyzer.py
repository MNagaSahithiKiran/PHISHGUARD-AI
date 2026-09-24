"""
PhishGuard AI - DOM Structure Analyzer.
Computes DOM tree depth, tag counts, text-to-HTML ratios, and hidden elements.
"""

from typing import Dict, Any
from bs4 import BeautifulSoup, Tag


def get_max_depth(tag: Tag, current_depth: int = 1) -> int:
    if not isinstance(tag, Tag) or not tag.contents:
        return current_depth
    child_depths = [
        get_max_depth(child, current_depth + 1)
        for child in tag.children
        if isinstance(child, Tag)
    ]
    return max(child_depths) if child_depths else current_depth


class DomAnalysisResult:
    def __init__(self, total_tags: int, dom_depth: int, text_ratio: float, hidden_elements_count: int, tag_frequencies: Dict[str, int] = None):
        self.total_tags = total_tags
        self.dom_depth = dom_depth
        self.text_ratio = text_ratio
        self.hidden_elements_count = hidden_elements_count
        self.tag_frequencies = tag_frequencies or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_tags": self.total_tags,
            "dom_depth": self.dom_depth,
            "text_ratio": round(self.text_ratio, 4),
            "hidden_elements_count": self.hidden_elements_count,
            "tag_frequencies": self.tag_frequencies,
        }


def analyze_dom(soup: BeautifulSoup) -> DomAnalysisResult:
    if not soup:
        return DomAnalysisResult(0, 0, 0.0, 0, {})

    all_tags = soup.find_all(True)
    node_count = len(all_tags)

    root = soup.find("html") or soup
    max_depth = get_max_depth(root) if root else 0

    hidden_count = 0
    tag_freq: Dict[str, int] = {}
    for tag in all_tags:
        name = tag.name.lower()
        tag_freq[name] = tag_freq.get(name, 0) + 1
        if tag.has_attr("hidden"):
            hidden_count += 1
            continue
        style = str(tag.get("style", "")).lower()
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
            hidden_count += 1

    raw_html_len = len(str(soup))
    text_len = len(soup.get_text(strip=True))
    text_ratio = text_len / max(1, raw_html_len)

    return DomAnalysisResult(
        total_tags=node_count,
        dom_depth=max_depth,
        text_ratio=text_ratio,
        hidden_elements_count=hidden_count,
        tag_frequencies=tag_freq,
    )


class DomAnalyzer:
    @staticmethod
    def analyze_dom(soup: BeautifulSoup, raw_html_len: int = 0, visible_text_len: int = 0) -> Dict[str, Any]:
        res = analyze_dom(soup)
        return {
            "node_count": res.total_tags,
            "max_dom_depth": res.dom_depth,
            "hidden_element_count": res.hidden_elements_count,
            "text_to_html_ratio": res.text_ratio,
        }

"""
PhishGuard AI - Evidence Fusion Service
Synthesizes factual, auditable findings from Phase 2 (URL), Phase 3 (HTTP/DOM/Headers),
and Phase 4 (Visual layout & aesthetic telemetry).
CRITICAL DEFENSE POLICIES:
- Missing security headers alone must NOT be described as proof of phishing.
- HTTPS alone must NOT imply legitimacy.
- A password field alone must NOT imply phishing.
- Evidence descriptions must remain purely factual.
"""

from typing import List, Dict, Any, Optional


class EvidenceItem:
    def __init__(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        source: str,
    ):
        self.category = category  # "network", "dom", "forms", "headers", "visual", "lexical"
        self.severity = severity  # "info", "low", "medium", "high", "critical"
        self.title = title
        self.description = description
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.source,
        }


class EvidenceFusionService:
    @classmethod
    def fuse_evidence(
        cls,
        website_evidence: Optional[List[Dict[str, Any]]] = None,
        visual_evidence: Optional[List[Dict[str, Any]]] = None,
        url_threat_indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Consolidates and normalizes evidence items across all analysis phases.
        """
        fused: List[Dict[str, Any]] = []
        seen_titles = set()

        # 1. Integrate Website Analysis Evidence (Phase 3)
        if website_evidence:
            for item in website_evidence:
                title = item.get("title", "")
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                fused.append({
                    "category": item.get("category", "website"),
                    "severity": item.get("severity", "medium"),
                    "title": title,
                    "description": item.get("detail", item.get("description", "")),
                    "source": "website_analyzer",
                })

        # 2. Integrate Visual Analysis Evidence (Phase 4)
        if visual_evidence:
            for item in visual_evidence:
                title = item.get("title", "")
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                fused.append({
                    "category": "visual",
                    "severity": item.get("severity", "medium"),
                    "title": title,
                    "description": item.get("description", ""),
                    "source": item.get("source", "visual_analyzer"),
                })

        # 3. Integrate Lexical URL Threat Indicators (Phase 1/2)
        if url_threat_indicators:
            for item in url_threat_indicators:
                title = item.get("rule_id", "LEXICAL_INDICATOR")
                if title in seen_titles:
                    continue
                seen_titles.add(title)
                fused.append({
                    "category": "lexical",
                    "severity": item.get("severity", "low"),
                    "title": title,
                    "description": item.get("description", ""),
                    "source": "url_rule_engine",
                })

        # Sort by severity priority: critical > high > medium > low > info
        priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        fused.sort(key=lambda x: priority.get(x["severity"].lower(), 5))
        return fused

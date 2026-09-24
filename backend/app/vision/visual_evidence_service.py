"""
PhishGuard AI - Visual Evidence Service
Produces structured, auditable security findings from visual model signals and layout telemetry.
Strictly adheres to evidence-based terminology:
Never claims "100% fake" or "definitely phishing". Uses transparent probabilistic reasoning.
"""

from typing import Dict, Any, List


class VisualEvidenceItem:
    def __init__(
        self,
        evidence_type: str,
        severity: str,
        title: str,
        description: str,
        source: str = "visual_model",
    ):
        self.evidence_type = evidence_type
        self.severity = severity  # "info", "low", "medium", "high", "critical"
        self.title = title
        self.description = description
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.source,
        }


def generate_visual_evidence(
    phishing_probability: float,
    model_name: str,
    visual_features: Dict[str, Any],
    layout_features: Dict[str, Any],
) -> List[VisualEvidenceItem]:
    """
    Synthesizes visual classifier outputs and layout metrics into auditable evidence findings.
    """
    evidence: List[VisualEvidenceItem] = []

    # 1. Direct Visual Model Signal
    prob_pct = round(phishing_probability * 100, 1)
    if phishing_probability >= 0.80:
        evidence.append(
            VisualEvidenceItem(
                evidence_type="visual_model_signal",
                severity="critical" if phishing_probability >= 0.92 else "high",
                title="Strong Visual Similarity to Phishing Templates",
                description=f"Computer vision model ({model_name}) produced a high phishing-class probability of {prob_pct}%, indicating strong visual resemblance to deceptive authentication pages.",
                source="visual_classifier",
            )
        )
    elif phishing_probability >= 0.50:
        evidence.append(
            VisualEvidenceItem(
                evidence_type="visual_model_signal",
                severity="medium",
                title="Moderate Visual Phishing Indicators",
                description=f"Visual classifier ({model_name}) produced an elevated phishing probability of {prob_pct}%. Spatial layout exhibits characteristics typical of credential interceptors.",
                source="visual_classifier",
            )
        )
    else:
        evidence.append(
            VisualEvidenceItem(
                evidence_type="visual_model_signal",
                severity="info",
                title="Visual Classifier Classified as Legitimate",
                description=f"Computer vision model ({model_name}) classified webpage appearance as consistent with benign web design (phishing probability: {prob_pct}%).",
                source="visual_classifier",
            )
        )

    # 2. Centered Card Form Layout
    if layout_features.get("has_centered_card_layout"):
        evidence.append(
            VisualEvidenceItem(
                evidence_type="layout_telemetry",
                severity="medium" if phishing_probability >= 0.50 else "low",
                title="Isolated Center Card Authentication Layout",
                description="Spatial decomposition detected structural complexity concentrated in the central 40% of the viewport, characteristic of standalone credential harvest dialogs.",
                source="layout_analyzer",
            )
        )

    # 3. High Whitespace Ratio with Low Edge Density
    whitespace = visual_features.get("whitespace_ratio", 0.0)
    edge_density = visual_features.get("edge_density", 0.0)
    if whitespace > 0.65 and edge_density < 0.03:
        evidence.append(
            VisualEvidenceItem(
                evidence_type="aesthetic_telemetry",
                severity="low",
                title="Sparse Minimalist Visual Density",
                description=f"Webpage exhibits high background whitespace ({round(whitespace*100, 1)}%) with low visual edge density, often seen in cloned single-purpose phishing portals.",
                source="visual_feature_extractor",
            )
        )

    return evidence

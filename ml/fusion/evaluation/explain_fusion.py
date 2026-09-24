"""
PhishGuard AI - Multi-Modal Explainability Engine
Generates human-auditable, factual multi-modal explanations synthesizing:
1. Final classification & calibrated probability.
2. Active modalities vs missing modalities.
3. Feature-level attributions (meta-model coefficients & SHAP).
4. Observed factual security evidence from DOM, forms, headers, and visual layout.
CRITICAL DEFENSE RULE: Strictly avoids unsupported speculations or claims of intent.
"""

from typing import Dict, Any, List, Optional


class MultiModalExplainer:
    @staticmethod
    def explain(
        classification: str,
        calibrated_probability: float,
        modalities_used: List[str],
        missing_modalities: List[str],
        base_models: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        feature_attributions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Constructs standardized, auditable multi-modal explanation.
        """
        prob_pct = round(calibrated_probability * 100.0, 1)

        # 1. High-level Summary
        if classification == "phishing":
            summary = (
                f"Multi-modal fusion estimated an elevated phishing probability of {prob_pct}%, "
                f"based on convergent signals across {', '.join(modalities_used)}."
            )
        elif classification == "suspicious":
            summary = (
                f"Multi-modal fusion estimated a borderline probability of {prob_pct}%, "
                f"falling within the documented uncertainty margin. Manual review or sandbox verification recommended."
            )
        else:
            summary = (
                f"Multi-modal fusion estimated a low phishing probability of {prob_pct}%, "
                f"consistent with benign web application design across analyzed modalities."
            )

        # 2. Key Model Signals
        model_signals = []
        if "url" in modalities_used and "url" in base_models:
            u_p = base_models["url"].get("probability")
            if u_p is not None:
                u_pct = round(u_p * 100.0, 1)
                desc = "elevated phishing probability" if u_p >= 0.50 else "benign lexical characteristics"
                model_signals.append(f"URL lexical model produced {u_pct}% ({desc}).")

        if "website" in modalities_used and "website" in base_models:
            w_p = base_models["website"].get("probability")
            if w_p is not None:
                w_pct = round(w_p * 100.0, 1)
                desc = "patterns associated with credential interception" if w_p >= 0.50 else "benign page structure"
                model_signals.append(f"Website DOM analyzer produced {w_pct}% ({desc}).")

        if "visual" in modalities_used and "visual" in base_models:
            v_p = base_models["visual"].get("probability")
            if v_p is not None:
                v_pct = round(v_p * 100.0, 1)
                desc = "visual layout similarity to deceptive login templates" if v_p >= 0.50 else "standard institutional visual layout"
                model_signals.append(f"Visual MobileNetV2 model produced {v_pct}% ({desc}).")

        # 3. Factual Observed Evidence
        observed_facts = []
        for ev in evidence_items:
            t = ev.get("title", "")
            d = ev.get("description", ev.get("detail", ""))
            observed_facts.append(f"{t}: {d}")

        # 4. Modality Status Summary
        modality_status = {
            "modalities_used": modalities_used,
            "missing_modalities": missing_modalities,
            "fusion_routing": "multimodal" if len(modalities_used) > 1 else "single_modality_fallback",
        }

        return {
            "summary": summary,
            "classification": classification,
            "calibrated_phishing_probability": round(calibrated_probability, 4),
            "key_model_signals": model_signals,
            "observed_factual_evidence": observed_facts,
            "modality_status": modality_status,
            "feature_attributions": feature_attributions or [],
        }

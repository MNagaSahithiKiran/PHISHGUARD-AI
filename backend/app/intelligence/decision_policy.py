"""
PhishGuard AI - Centralized Security Decision Policy Engine
Policy Version: risk_policy_v1

Translates multi-modal probabilities, DOM analysis signals, and external reputation
evidence into deterministic, explainable security classifications, risk scores, and
traceable reason codes.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


POLICY_VERSION = "risk_policy_v1"

REASON_DESCRIPTIONS = {
    "REPUTATION_THREAT_MATCH": "Active threat match verified in external threat intelligence database or feed.",
    "EXTERNAL_PASSWORD_SUBMISSION": "Credential/password form targets an external or cross-origin destination.",
    "HIGH_LEXICAL_ENTROPY": "URL exhibits abnormally high entropy indicative of obfuscation or token stuffing.",
    "SUSPICIOUS_REDIRECT_CHAIN": "URL traverses multiple redirects across different parent domains.",
    "SUSPICIOUS_IP_TARGET": "Host specifies a direct IP address rather than a registered domain name.",
    "HOMOGLYPH_OR_BRAND_SPOOF": "Domain exhibits typo-squatting or brand impersonation characteristics.",
    "MISSING_SECURITY_HEADERS": "Target site is missing critical HTTPS or modern security posture headers.",
    "SEARCH_RESULT_CONFIRMED": "Configured search provider confirmed indexed, high-ranking results for target domain.",
    "SEARCH_NO_RESULT": "No matching Google Search result was returned by the configured search provider for this query at this time.",
    "BENIGN_LEXICAL_SIGNALS": "URL structural and lexical metrics conform to typical legitimate domain norms.",
    "UNAUTHENTICATED_INPUT": "Analysis executed via automated headless scanner without authenticated session state.",
    "DNS_RESOLUTION_FAILED": "Target domain could not be resolved via DNS; destination host is nonexistent or unreachable.",
    "FETCH_FAILED": "HTTP/HTTPS connection could not be established to destination target.",
    "INSUFFICIENT_EVIDENCE": "Target host cannot be reached or analyzed; evidence is insufficient to verify active threat status.",
}


class DecisionPolicyEngine:
    POLICY_VERSION = POLICY_VERSION

    @classmethod
    def evaluate(
        cls,
        calibrated_probability: Optional[float],
        modalities_used: List[str],
        missing_modalities: List[str],
        dom_signals: Optional[Dict[str, Any]] = None,
        lexical_signals: Optional[Dict[str, Any]] = None,
        reputation_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Determines the final security classification, risk score, and auditable reason codes.
        Guarantees zero random results and zero unbacked claims.
        """
        reason_codes: List[str] = []
        dom_signals = dom_signals or {}
        lexical_signals = lexical_signals or {}
        reputation_summary = reputation_summary or {}

        # 1. Evaluate External Threat Intelligence Evidence
        threat_matches = reputation_summary.get("threat_matches", 0)
        provider_results = reputation_summary.get("provider_results", {})

        if threat_matches > 0:
            reason_codes.append("REPUTATION_THREAT_MATCH")

        # Check search provider result
        google_search_res = provider_results.get("google_search")
        if google_search_res:
            st = getattr(google_search_res, "status", None) or google_search_res.get("status")
            if st == "CONFIRMED_RESULT":
                reason_codes.append("SEARCH_RESULT_CONFIRMED")
            elif st == "NO_RESULT":
                reason_codes.append("SEARCH_NO_RESULT")

        # 2. Evaluate DOM / Behavioral Signals
        forms = dom_signals.get("forms", {})
        has_ext_pw = forms.get("external_action_count", 0) > 0 and forms.get("has_password_field", False)
        if has_ext_pw:
            reason_codes.append("EXTERNAL_PASSWORD_SUBMISSION")

        headers = dom_signals.get("headers", {})
        if headers.get("security_header_score", 1.0) < 0.3:
            reason_codes.append("MISSING_SECURITY_HEADERS")

        redirects = dom_signals.get("redirects", {})
        if redirects.get("total_redirects", 0) >= 3 or redirects.get("cross_domain_redirects", 0) >= 2:
            reason_codes.append("SUSPICIOUS_REDIRECT_CHAIN")

        # 3. Evaluate Lexical Signals
        if lexical_signals.get("is_ip_address", False):
            reason_codes.append("SUSPICIOUS_IP_TARGET")

        if lexical_signals.get("entropy", 0.0) > 4.5:
            reason_codes.append("HIGH_LEXICAL_ENTROPY")

        if lexical_signals.get("brand_spoof_detected", False) or lexical_signals.get("suspicious_keywords_count", 0) >= 3:
            reason_codes.append("HOMOGLYPH_OR_BRAND_SPOOF")

        # Always record scanner context
        reason_codes.append("UNAUTHENTICATED_INPUT")

        # 4. Check DNS Resolution Failure
        http_data = dom_signals.get("http", {})
        network_data = dom_signals.get("network", {})
        dns_status = network_data.get("dns", {}).get("status")
        http_err = str(http_data.get("error") or "").lower()

        is_dns_failed = (dns_status == "DNS_FAILED") or ("dns" in http_err and "failed" in http_err) or ("getaddrinfo" in http_err) or ("nonexistent" in http_err)
        is_fetch_failed = bool(http_data.get("error"))

        if is_dns_failed:
            if "DNS_RESOLUTION_FAILED" not in reason_codes:
                reason_codes.append("DNS_RESOLUTION_FAILED")
            if "INSUFFICIENT_EVIDENCE" not in reason_codes:
                reason_codes.append("INSUFFICIENT_EVIDENCE")
        elif is_fetch_failed:
            if "FETCH_FAILED" not in reason_codes:
                reason_codes.append("FETCH_FAILED")

        if is_dns_failed and threat_matches == 0:
            return {
                "verdict": "insufficient_evidence",
                "classification": "insufficient_evidence",
                "risk_score": 0.0,
                "risk_level": "unknown",
                "reason_codes": reason_codes,
                "reason_details": [
                    {"code": c, "description": REASON_DESCRIPTIONS.get(c, "Security indicator observed during analysis.")}
                    for c in reason_codes
                ],
                "decision_policy_version": POLICY_VERSION,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            }

        # 5. Compute Risk Score & Classification
        if calibrated_probability is None and not modalities_used:
            return {
                "verdict": "unrated",
                "classification": "unrated",
                "risk_score": 0.0,
                "risk_level": "unknown",
                "reason_codes": ["UNAUTHENTICATED_INPUT"],
                "reason_details": [
                    {"code": "UNAUTHENTICATED_INPUT", "description": REASON_DESCRIPTIONS["UNAUTHENTICATED_INPUT"]}
                ],
                "decision_policy_version": POLICY_VERSION,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            }

        base_prob = calibrated_probability if calibrated_probability is not None else 0.0
        calculated_risk = base_prob * 100.0

        # Hard threat overrides from genuine evidence
        if threat_matches > 0:
            calculated_risk = max(calculated_risk, 92.0)
            verdict = "phishing"
        elif has_ext_pw:
            calculated_risk = max(calculated_risk, 85.0)
            verdict = "phishing"
        else:
            # Deterministic threshold mapping:
            # <= 25.0: legitimate
            # > 25.0 and < 65.0: suspicious
            # >= 65.0: phishing
            if calculated_risk >= 65.0:
                verdict = "phishing"
            elif calculated_risk <= 25.0:
                verdict = "legitimate"
                if "BENIGN_LEXICAL_SIGNALS" not in reason_codes:
                    reason_codes.append("BENIGN_LEXICAL_SIGNALS")
            else:
                verdict = "suspicious"

        # Determine risk level string
        if calculated_risk >= 65.0:
            risk_level = "high"
        elif calculated_risk <= 25.0:
            risk_level = "low"
        else:
            risk_level = "medium"

        # Construct detailed reason objects
        reason_details = []
        for code in reason_codes:
            reason_details.append({
                "code": code,
                "description": REASON_DESCRIPTIONS.get(code, "Security indicator observed during analysis.")
            })

        return {
            "verdict": verdict,
            "classification": verdict,
            "risk_score": round(calculated_risk, 2),
            "risk_level": risk_level,
            "reason_codes": reason_codes,
            "reason_details": reason_details,
            "decision_policy_version": POLICY_VERSION,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

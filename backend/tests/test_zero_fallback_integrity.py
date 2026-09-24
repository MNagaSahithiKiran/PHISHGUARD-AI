import pytest
from app.intelligence.decision_policy import DecisionPolicyEngine, POLICY_VERSION


def test_decision_policy_threat_override():
    res = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.1,
        modalities_used=["url"],
        missing_modalities=["website", "visual"],
        reputation_summary={"threat_matches": 1, "provider_results": {}},
    )
    assert res["verdict"] == "phishing"
    assert res["risk_score"] >= 90.0
    assert "REPUTATION_THREAT_MATCH" in res["reason_codes"]
    assert res["decision_policy_version"] == POLICY_VERSION


def test_decision_policy_external_password():
    res = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.2,
        modalities_used=["url", "website"],
        missing_modalities=["visual"],
        dom_signals={
            "forms": {"external_action_count": 1, "has_password_field": True}
        }
    )
    assert res["verdict"] == "phishing"
    assert res["risk_score"] >= 85.0
    assert "EXTERNAL_PASSWORD_SUBMISSION" in res["reason_codes"]


def test_decision_policy_benign():
    res = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.08,
        modalities_used=["url", "website"],
        missing_modalities=["visual"],
        dom_signals={"forms": {}, "headers": {"security_header_score": 0.9}},
        lexical_signals={"entropy": 2.1, "is_ip_address": False},
        reputation_summary={"threat_matches": 0, "provider_results": {
            "google_search": {"status": "CONFIRMED_RESULT"}
        }}
    )
    assert res["verdict"] == "legitimate"
    assert res["risk_score"] <= 25.0
    assert "BENIGN_LEXICAL_SIGNALS" in res["reason_codes"]
    assert "SEARCH_RESULT_CONFIRMED" in res["reason_codes"]


def test_decision_policy_search_no_result():
    res = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.35,
        modalities_used=["url"],
        missing_modalities=["website", "visual"],
        reputation_summary={"threat_matches": 0, "provider_results": {
            "google_search": {"status": "NO_RESULT"}
        }}
    )
    assert "SEARCH_NO_RESULT" in res["reason_codes"]
    assert res["verdict"] == "suspicious"


def test_decision_policy_empty_input():
    res = DecisionPolicyEngine.evaluate(
        calibrated_probability=None,
        modalities_used=[],
        missing_modalities=["url", "website", "visual"],
    )
    assert res["verdict"] == "unrated"
    assert res["risk_score"] == 0.0
    assert res["decision_policy_version"] == POLICY_VERSION

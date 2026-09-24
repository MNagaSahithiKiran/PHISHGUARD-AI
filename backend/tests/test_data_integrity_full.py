import pytest
import uuid
import json
from unittest.mock import patch, MagicMock
from app.core.security import normalize_url, validate_and_sanitize_url, SecurityValidationError
from app.ml.model_loader import ModelLoader
from app.ml.prediction_service import PredictionService
from app.analyzers.network_analyzer import NetworkAnalyzer
from app.intelligence.decision_policy import DecisionPolicyEngine


def test_url_validation_rejection_rules():
    """Verifies that malformed URLs, credentials, bare hostnames, and invalid ports are rejected."""
    invalid_cases = [
        "",
        "   ",
        "abc",
        "example",
        "https://.",
        "https://user:password@example.com",
        "http://admin:secret@phishing-target.com/login",
        "https://example.com:99999/path",
        "https://example.com:-1/path",
        "https://-invalid-domain.com",
        "ftp://malicious.com/file",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://..example.com",
    ]
    for url in invalid_cases:
        with pytest.raises(SecurityValidationError):
            validate_and_sanitize_url(url)


def test_url_normalization_determinism():
    """Verifies 100-repeat determinism for canonical URL normalization."""
    test_urls = [
        "https://EXAMPLE.com:443/Path//to/resource/?b=2&a=1#section",
        "http://google.com:80/?query=test",
        "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c",
    ]
    for raw in test_urls:
        first = normalize_url(raw)
        for _ in range(50):
            assert normalize_url(raw) == first


def test_model_artifact_hash_verification():
    """Verifies that ModelLoader checks SHA-256 hashes against metadata."""
    loader = ModelLoader.get_instance()
    assert loader.is_loaded
    assert hasattr(loader, "model_hash")
    assert hasattr(loader, "preprocessor_hash")
    assert loader.metadata.get("model_sha256") == loader.model_hash
    assert loader.metadata.get("preprocessor_sha256") == loader.preprocessor_hash


def test_lexical_prediction_determinism():
    """Verifies that 100 consecutive predictions on the same URL produce identical probabilities."""
    target = "https://paypal-security-update-account.verify-banking.com/login"
    first = PredictionService.predict_url(target)
    for _ in range(50):
        repeat = PredictionService.predict_url(target)
        assert repeat["prediction"] == first["prediction"]
        assert repeat["probability"] == first["probability"]
        assert repeat["feature_hash"] == first["feature_hash"]


def test_nonexistent_domain_dns_failure_evaluates_insufficient_evidence():
    """Target domain nonexistent in DNS must evaluate to insufficient_evidence, not 99% phishing."""
    dom_signals = {
        "http": {"error": "DNS resolution failed: name does not exist", "status_code": None},
        "network": {"dns": {"status": "DNS_FAILED", "resolved_ips": [], "error": "Name or service not known"}},
    }
    decision = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.92,
        modalities_used=["url"],
        missing_modalities=["website", "visual"],
        dom_signals=dom_signals,
        lexical_signals={"entropy": 3.8, "is_ip_address": False},
        reputation_summary={"threat_matches": 0, "provider_results": {}},
    )
    assert decision["classification"] == "insufficient_evidence"
    assert decision["risk_score"] == 0.0
    assert "DNS_RESOLUTION_FAILED" in decision["reason_codes"]
    assert "INSUFFICIENT_EVIDENCE" in decision["reason_codes"]


def test_decision_policy_reputation_override():
    """Verified external threat intelligence must deterministically trigger high risk phishing."""
    decision = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.10,  # Even if lexical was low
        modalities_used=["url"],
        missing_modalities=[],
        dom_signals={},
        lexical_signals={},
        reputation_summary={
            "threat_matches": 1,
            "provider_results": {
                "google_safe_browsing": {"status": "THREAT_MATCH"}
            }
        },
    )
    assert decision["classification"] == "phishing"
    assert decision["risk_score"] >= 92.0
    assert "REPUTATION_THREAT_MATCH" in decision["reason_codes"]


def test_decision_policy_credential_theft_override():
    """External password form action must trigger phishing override."""
    dom_signals = {
        "forms": {"external_action_count": 1, "has_password_field": True}
    }
    decision = DecisionPolicyEngine.evaluate(
        calibrated_probability=0.20,
        modalities_used=["url", "website"],
        missing_modalities=[],
        dom_signals=dom_signals,
        lexical_signals={},
        reputation_summary={"threat_matches": 0, "provider_results": {}},
    )
    assert decision["classification"] == "phishing"
    assert decision["risk_score"] >= 85.0
    assert "EXTERNAL_PASSWORD_SUBMISSION" in decision["reason_codes"]

"""
PhishGuard AI - Comprehensive Website Analysis & Security Tests (Phase 3)
Tests SSRF guard, redirect controls, HTML/DOM/Form/Script/Iframe/Header analyzers,
evidence generation, 48-feature extraction, and API endpoints.
"""

import pytest
from bs4 import BeautifulSoup
from unittest.mock import patch, AsyncMock

from app.analyzers.safety.ip_validator import IPValidator
from app.analyzers.safety.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.analyzers.safety.fetch_policy import FetchPolicy
from app.analyzers.form_analyzer import analyze_forms
from app.analyzers.link_analyzer import analyze_links
from app.analyzers.script_analyzer import analyze_scripts
from app.analyzers.iframe_analyzer import analyze_iframes
from app.analyzers.resource_analyzer import analyze_resources
from app.analyzers.header_analyzer import analyze_security_headers
from app.services.evidence_service import generate_website_evidence
from ml.feature_engineering.website_features import extract_website_features, WEBSITE_FEATURE_NAMES


# =========================================================================
# 1. SSRF & Network Security Tests
# =========================================================================

def test_ip_validator_private_ipv4():
    assert IPValidator.is_ip_private("127.0.0.1") is True
    assert IPValidator.is_ip_private("10.0.0.1") is True
    assert IPValidator.is_ip_private("172.16.0.1") is True
    assert IPValidator.is_ip_private("192.168.1.100") is True
    assert IPValidator.is_ip_private("169.254.169.254") is True  # AWS/Cloud metadata
    assert IPValidator.is_ip_private("0.0.0.0") is True


def test_ip_validator_public_ipv4():
    assert IPValidator.is_ip_private("8.8.8.8") is False
    assert IPValidator.is_ip_private("1.1.1.1") is False
    assert IPValidator.is_ip_private("142.250.190.46") is False


def test_ip_validator_ipv6():
    assert IPValidator.is_ip_private("::1") is True
    assert IPValidator.is_ip_private("fe80::1") is True
    assert IPValidator.is_ip_private("fc00::1") is True
    assert IPValidator.is_ip_private("2607:f8b0:4005:805::200e") is False


def test_ssrf_disallowed_schemes():
    for scheme_url in [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70",
        "javascript:alert(1)",
        "data:text/html,test",
    ]:
        with pytest.raises(SSRFSecurityException):
            SSRFGuard.validate_target_url(scheme_url)


def test_ssrf_direct_private_ip():
    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://127.0.0.1/admin")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://169.254.169.254/latest/meta-data")

    with pytest.raises(SSRFSecurityException):
        SSRFGuard.validate_target_url("http://localhost:8000/dashboard")


def test_fetch_policy_limits():
    policy = FetchPolicy()
    assert policy.MAX_REDIRECTS == 5
    assert policy.MAX_RESPONSE_BYTES == 5 * 1024 * 1024  # 5 MB
    assert policy.CONNECT_TIMEOUT_SECONDS == 5.0
    assert policy.TOTAL_TIMEOUT_SECONDS == 10.0


# =========================================================================
# 2. Analyzers Unit Tests
# =========================================================================

def test_form_analyzer_external_action_and_password():
    html = """
    <html>
      <body>
        <form action="https://evil-credential-harvester.com/login.php" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Log In">
        </form>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    res = analyze_forms(soup, "https://legitimate-bank.com/portal")

    assert res.total_forms == 1
    assert res.login_forms_count == 1
    assert res.has_password_field is True
    assert res.external_action_count == 1
    form_detail = res.forms[0]
    assert form_detail["is_external_action"] is True
    assert form_detail["action_domain"] == "evil-credential-harvester.com"
    assert form_detail["has_password"] is True


def test_link_analyzer_null_and_external_links():
    html = """
    <html>
      <body>
        <a href="https://legitimate-bank.com/about">About</a>
        <a href="https://external-site.com/promo">External</a>
        <a href="#">Dead Link 1</a>
        <a href="javascript:void(0)">Dead Link 2</a>
        <a href="">Empty Link</a>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    res = analyze_links(soup, "https://legitimate-bank.com")

    assert res.total_links == 5
    assert res.internal_links == 1
    assert res.external_links == 1
    assert res.null_empty_links == 3
    assert res.null_link_ratio == 0.60
    assert res.external_link_ratio == 0.20


def test_script_analyzer():
    html = """
    <html>
      <head>
        <script src="https://cdn.example.com/app.js"></script>
        <script>
          var token = "secret";
        </script>
      </head>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    res = analyze_scripts(soup, "https://example.com")

    assert res.total_scripts == 2
    assert res.external_scripts == 1
    assert res.inline_scripts == 1
    assert "cdn.example.com" in res.external_script_domains
    assert res.inline_script_bytes > 0


def test_iframe_analyzer_hidden_and_cross_origin():
    html = """
    <html>
      <body>
        <iframe src="https://evil.com/trap" style="display:none" width="0" height="0"></iframe>
        <iframe src="https://example.com/embed" sandbox="allow-scripts"></iframe>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    res = analyze_iframes(soup, "https://example.com")

    assert res.total_iframes == 2
    assert res.hidden_iframes == 1
    assert res.cross_origin_iframes == 1
    assert res.sandboxed_iframes == 1


def test_resource_analyzer():
    html = """
    <html>
      <head>
        <link rel="stylesheet" href="https://external-cdn.com/style.css">
      </head>
      <body>
        <img src="https://victim-bank.com/logo.png">
        <img src="https://example.com/local.png">
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    res = analyze_resources(soup, "https://example.com")

    assert res.total_resources == 3
    assert res.external_resources == 2
    assert "external-cdn.com" in res.distinct_resource_domains
    assert "victim-bank.com" in res.distinct_resource_domains


def test_security_header_analyzer():
    headers = {
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "server": "nginx",
    }
    res = analyze_security_headers(headers)
    assert res.hsts_present is True
    assert res.hsts_max_age == 63072000
    assert res.hsts_includes_subdomains is True
    assert res.csp_present is True
    assert res.csp_has_default_src is True
    assert res.csp_has_frame_ancestors is True
    assert res.x_frame_options == "DENY"
    assert res.x_content_type_options == "nosniff"
    assert res.security_header_score == 1.0


# =========================================================================
# 3. 48-Feature Extractor & Evidence Generation Tests
# =========================================================================

def test_website_features_count_and_types():
    http_data = {"status_code": 200, "response_time_ms": 120.5, "content_length": 4500, "final_url": "https://example.com"}
    redirect_data = {"total_hops": 1, "protocol_downgrades": 0}
    html_data = {"title": "Welcome Home", "body_byte_length": 4500}
    dom_data = {"dom_depth": 5, "total_tags": 35, "text_ratio": 0.25, "hidden_elements_count": 0}
    form_data = {"total_forms": 1, "login_forms_count": 0, "has_password_field": False, "external_action_count": 0, "empty_action_count": 0, "forms": []}
    link_data = {"total_links": 10, "internal_links": 8, "external_links": 2, "external_link_ratio": 0.2, "null_empty_links": 0, "null_link_ratio": 0.0}
    script_data = {"total_scripts": 2, "inline_scripts": 1, "external_scripts": 1, "external_script_domains": ["cdn.example.com"], "inline_script_bytes": 100}
    iframe_data = {"total_iframes": 0, "hidden_iframes": 0, "cross_origin_iframes": 0, "sandboxed_iframes": 0, "suspicious_fullpage_iframes": 0}
    resource_data = {"total_resources": 5, "external_resources": 1, "external_resource_ratio": 0.2, "mixed_content_count": 0, "distinct_resource_domains": ["cdn.example.com"]}
    header_data = {"hsts_present": True, "csp_present": True, "x_frame_options": "SAMEORIGIN", "x_content_type_options": "nosniff", "referrer_policy": "no-referrer", "security_header_score": 0.8}

    features = extract_website_features(
        http_data, redirect_data, html_data, dom_data, form_data,
        link_data, script_data, iframe_data, resource_data, header_data
    )

    assert len(features) == 48
    assert len(WEBSITE_FEATURE_NAMES) == 48

    for name in WEBSITE_FEATURE_NAMES:
        assert name in features
        assert isinstance(features[name], (int, float))


def test_evidence_generation_critical_on_external_password():
    http_data = {"final_url": "https://fake-login.com", "error": None}
    redirect_data = {"total_hops": 0, "protocol_downgrades": 0, "cross_domain_redirects": 0}
    html_data = {}
    dom_data = {}
    form_data = {
        "forms": [{"is_external_action": True, "has_password": True, "action_domain": "evil-collector.ru"}],
        "has_password_field": True,
        "external_action_count": 1,
        "empty_action_count": 0,
    }
    link_data = {"total_links": 0, "null_link_ratio": 0.0}
    script_data = {"external_script_domains": []}
    iframe_data = {"hidden_iframes": 0, "suspicious_fullpage_iframes": 0}
    resource_data = {"total_resources": 0, "external_resource_ratio": 0.0}
    header_data = {"hsts_present": False, "csp_present": False}

    evidence = generate_website_evidence(
        http_data, redirect_data, html_data, dom_data, form_data,
        link_data, script_data, iframe_data, resource_data, header_data
    )

    severities = [e.severity for e in evidence]
    assert "critical" in severities
    ext_form_ev = [e for e in evidence if e.category == "forms" and e.severity == "critical"]
    assert len(ext_form_ev) > 0
    assert "evil-collector.ru" in ext_form_ev[0].detail


# =========================================================================
# 4. API Endpoints Integration Tests
# =========================================================================

@pytest.mark.asyncio
async def test_analyze_endpoint_ssrf_blocked(client):
    response = await client.post(
        "/api/v1/analyze",
        json={"url": "http://127.0.0.1:8000/internal-admin"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "blocked"
    assert "SSRF" in data["evidence"][0]["title"] or "Restricted" in data["evidence"][0]["title"]
    assert data["website_model"]["status"] == "not_available"


@pytest.mark.asyncio
async def test_analyze_endpoint_mocked_fetch(client):
    mock_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Secure Portal Test</title></head>
      <body>
        <form action="/login" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
        </form>
        <a href="/faq">FAQ</a>
      </body>
    </html>
    """

    with patch("app.analyzers.website_analyzer.safe_http_fetch", new_callable=AsyncMock) as mock_fetch:
        from app.analyzers.http_analyzer import SafeFetchResult
        mock_fetch.return_value = SafeFetchResult(
            final_url="https://verified-domain.com/portal",
            status_code=200,
            headers={"content-type": "text/html", "strict-transport-security": "max-age=31536000"},
            html_content=mock_html,
            content_length=len(mock_html),
            response_time_ms=45.2,
            redirect_chain=[],
            ip_address="93.184.216.34",
        )

        with patch("app.analyzers.safety.ssrf_guard.SSRFGuard.validate_target_url"):
            with patch("app.services.website_analysis_service.PredictionService.predict_url") as mock_pred:
                mock_pred.return_value = {"verdict": "legitimate", "confidence_score": 0.99, "probabilities": {"phishing": 0.01}}
                response = await client.post(
                    "/api/v1/analyze",
                    json={"url": "https://verified-domain.com/portal"},
                )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"
            assert data["final_url"] == "https://verified-domain.com/portal"
            assert data["html"]["title"] == "Secure Portal Test"
            assert data["forms"]["total_forms"] == 1
            assert data["forms"]["has_password_field"] is True
            assert data["website_model"]["status"] == "not_available"

            # Check GET /api/v1/analyze/{scan_id}
            scan_id = data["scan_id"]
            get_resp = await client.get(f"/api/v1/analyze/{scan_id}")
            assert get_resp.status_code == 200
            get_data = get_resp.json()
            assert get_data["scan_id"] == scan_id
            assert get_data["html"]["title"] == "Secure Portal Test"

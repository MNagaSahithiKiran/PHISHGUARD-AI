import pytest
from app.core.security import validate_and_sanitize_url, SecurityValidationError


def test_valid_urls_sanitize_properly():
    res = validate_and_sanitize_url("https://www.example.com/login?ref=1")
    assert res["scheme"] == "https"
    assert res["hostname"] == "www.example.com"
    assert res["domain"] == "example.com"
    assert res["path"] == "/login"


def test_ssrf_blocks_localhost():
    with pytest.raises(SecurityValidationError) as exc:
        validate_and_sanitize_url("http://localhost/admin")
    assert "SSRF Protection" in str(exc.value.detail)


def test_ssrf_blocks_loopback_ip():
    with pytest.raises(SecurityValidationError) as exc:
        validate_and_sanitize_url("http://127.0.0.1:8000/api")
    assert "SSRF Protection" in str(exc.value.detail)


def test_ssrf_blocks_private_subnets():
    private_ips = [
        "http://192.168.1.1/router",
        "http://10.0.0.1/secret",
        "http://172.16.0.5/dashboard",
        "http://169.254.169.254/latest/meta-data/"
    ]
    for url in private_ips:
        with pytest.raises(SecurityValidationError) as exc:
            validate_and_sanitize_url(url)
        assert "SSRF Protection" in str(exc.value.detail)


def test_invalid_schemes_rejected():
    disallowed = [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "javascript:alert(1)"
    ]
    for url in disallowed:
        with pytest.raises(SecurityValidationError):
            validate_and_sanitize_url(url)

import pytest
from datetime import timedelta
import jwt
from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.models.user import User


@pytest.mark.asyncio
async def test_authentication_bypass_rejection(client):
    """Verifies that protected routes reject unauthenticated requests with HTTP 401."""
    # 1. No token provided
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401

    # 2. Malformed token format
    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-valid-jwt-token"},
    )
    assert res.status_code == 401

    # 3. Forged token signed with an invalid attacker key
    forged_token = jwt.encode(
        {"sub": "attacker@evil.com", "role": "admin"},
        key="completely-different-signing-key-attacker",
        algorithm="HS256",
    )
    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_expired_token_rejection(client):
    """Verifies that expired JWT tokens are immediately rejected."""
    # Create token that expired 10 minutes ago
    expired_token = create_access_token(
        {"sub": "analyst-id", "role": "analyst"},
        expires_delta=timedelta(minutes=-10),
    )
    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_privilege_escalation_prevention(client, db_session):
    """Verifies that regular analysts cannot access restricted administrative routes (HTTP 403)."""
    # Create standard analyst user
    analyst_user = User(
        email="regular_analyst@phishguard.ai",
        hashed_password=hash_password("AnalystPass2026!"),
        full_name="SOC Analyst",
        role="analyst",
        is_active=True,
    )
    db_session.add(analyst_user)
    await db_session.commit()
    await db_session.refresh(analyst_user)

    analyst_token = create_access_token(
        {"sub": analyst_user.id, "email": analyst_user.email, "role": "analyst"}
    )

    # Attempt to access admin-only user management endpoint
    res = await client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 403
    assert "admin" in res.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_ssrf_guardrail_revalidation(client):
    """Revalidates Phase 3 SSRF protections against internal, link-local, loopback, and metadata IPs."""
    forbidden_targets = [
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
        "http://localhost",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/router",
        "http://172.16.0.1/internal",
        "http://169.254.169.254/latest/meta-data/",  # AWS / Cloud metadata
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/",
        "ftp://anonymous@internal.corp/",
    ]

    for target in forbidden_targets:
        res = await client.post("/api/v1/scans", json={"url": target})
        # Must be rejected before outbound network egress (400 or 422)
        assert res.status_code in (400, 422), f"Target '{target}' was not blocked! Status: {res.status_code}"


@pytest.mark.asyncio
async def test_sqli_payload_resilience(client):
    """Verifies that SQL injection payloads in parameters do not execute or cause database syntax errors."""
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "1; DROP TABLE scans; --",
        "' UNION SELECT id, email, hashed_password FROM users --",
    ]

    for payload in sqli_payloads:
        # Test in scan query parameters
        res = await client.get(f"/api/v1/scans?search={payload}")
        # Endpoint must return HTTP 200 with empty/clean results, never 500
        assert res.status_code == 200, f"SQLi payload triggered failure: {payload}"


@pytest.mark.asyncio
async def test_security_headers_presence(client):
    """Verifies that all responses include strict security hardening headers."""
    res = await client.get("/")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert "X-Correlation-ID" in headers
    assert "X-Request-ID" in headers


@pytest.mark.asyncio
async def test_rate_limiting_enforcement(client):
    """Verifies that exceeding configured rate limits returns HTTP 429 Too Many Requests."""
    rate_limited = False
    for _ in range(25):
        res = await client.post(
            "/api/v1/auth/login",
            data={"username": "unknown@domain.com", "password": "wrongpassword"},
        )
        if res.status_code == 429:
            rate_limited = True
            assert "too many" in res.json().get("detail", "").lower()
            break

    assert rate_limited is True, "Rate limiter did not trigger HTTP 429!"

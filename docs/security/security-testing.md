# Security Hardening & Penetration Testing Report

## 1. Methodology
PhishGuard AI was subjected to automated and manual security testing covering OWASP Top 10 vulnerabilities, SSRF protection boundaries, and authentication bypass vectors.

---

## 2. Test Execution Matrix

| Test Category | Target Vector | Observed Behavior | Status |
| :--- | :--- | :--- | :--- |
| **Authentication** | Missing token | HTTP 401 Unauthorized | PASS |
| **Authentication** | Malformed / tampered JWT | HTTP 401 Unauthorized | PASS |
| **Authentication** | Forged signature with invalid key | HTTP 401 Unauthorized | PASS |
| **Authentication** | Expired token | HTTP 401 Unauthorized (token rejected) | PASS |
| **Authorization / RBAC**| Analyst accessing `/admin/users` | HTTP 403 Forbidden | PASS |
| **IDOR** | Direct object access without ownership | Scope restricted by user_id | PASS |
| **SQL Injection** | `' OR '1'='1`, `UNION SELECT` | Parameterized SQLAlchemy query | PASS |
| **SSRF (Loopback)** | `http://127.0.0.1`, `localhost` | Blocked pre-flight (HTTP 400/422) | PASS |
| **SSRF (Private IP)** | `10.0.0.1`, `192.168.1.1`, `172.16.0.1` | Blocked pre-flight (HTTP 400/422) | PASS |
| **SSRF (Cloud Metadata)**| `http://169.254.169.254/latest/meta-data/` | Blocked pre-flight (HTTP 400/422) | PASS |
| **SSRF (Non-HTTP)** | `file:///etc/passwd`, `gopher://` | Blocked pre-flight (HTTP 400/422) | PASS |
| **Rate Limiting** | Rapid brute-force login attempts | HTTP 429 Too Many Requests | PASS |
| **Payload Limiting**| Oversized request body (> 10MB) | HTTP 413 Payload Too Large | PASS |
| **Security Headers**| nosniff, DENY, CSP, correlation ID | All present on responses | PASS |

---

## 3. Automated Verification Command
```bash
python -m pytest backend/tests/test_security_hardening.py -v
```
Output:
```
backend/tests/test_security_hardening.py::test_authentication_bypass_rejection PASSED
backend/tests/test_security_hardening.py::test_expired_token_rejection PASSED
backend/tests/test_security_hardening.py::test_privilege_escalation_prevention PASSED
backend/tests/test_security_hardening.py::test_ssrf_guardrail_revalidation PASSED
backend/tests/test_security_hardening.py::test_sqli_payload_resilience PASSED
backend/tests/test_security_hardening.py::test_security_headers_presence PASSED
backend/tests/test_security_hardening.py::test_rate_limiting_enforcement PASSED
7 passed in 1.12s
```

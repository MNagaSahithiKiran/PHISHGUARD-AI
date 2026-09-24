# PhishGuard AI — Application Security Specification

## Security Architecture Overview
PhishGuard AI operates in potentially adversarial environments where target URLs, submitted DOM structures, and external network responses may be crafted to exploit security scanners. Consequently, defense-in-depth is enforced across the application lifecycle.

---

## Defensive Guardrails Matrix

| Layer | Threat Model | Defensive Mechanism | Enforcement Location |
|---|---|---|---|
| **Network / Ingestion** | Server-Side Request Forgery (SSRF), VPC Scanning | DNS pre-resolution, RFC 1918 blocking, loopback rejection | `app/core/security.py`, `app/analyzers/safety/` |
| **Authentication** | Credential Stuffing, Brute-Force Attacks | Bcrypt salt hashing, Sliding-window IP rate limiter | `app/core/security.py`, `app/main.py` |
| **Session Security** | Token Tampering, Replay Attacks | HMAC-SHA256 JWT tokens with strict expiration (`exp`) | `app/core/security.py`, `app/api/deps.py` |
| **Authorization** | Broken Object Level Auth (IDOR), Privilege Escalation | Explicit RBAC checks (`user` vs `admin`) on sensitive endpoints | `app/api/deps.py` |
| **Browser Execution** | Remote Code Execution, Sandbox Escape | Isolated headless sandboxing, strict timeouts, content size caps | `app/analyzers/safety/fetch_policy.py` |
| **Data Egress / Reporting** | CSV Injection, PDF Scripting | RFC 4180 escaping, ReportLab vector canvas (no executable JS) | `app/reports/pdf_report_service.py` |
| **HTTP Transport** | Clickjacking, MIME sniffing, Cross-Site Scripting | Defensive HTTP Headers (`CSP`, `X-Frame: DENY`, `X-Content-Type`) | `app/main.py` |

---

## Detailed Security Policies

### 1. Server-Side Request Forgery (SSRF) Protection
Before establishing any socket connection:
1. Scheme verification: Only `http://` and `https://` schemes are admitted.
2. Hostname validation: Rejects loopback aliases (`localhost`, `127.0.0.1`, `[::1]`).
3. DNS resolution validation: Resolves A and AAAA records via standard DNS. Each returned IP is verified against:
   - Private subnets: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
   - Link-local addresses: `169.254.0.0/16`.
   - Multicast and reserved blocks: `224.0.0.0/4`, `240.0.0.0/4`.
   - Cloud metadata IP: `169.254.169.254`.

### 2. Password Storage & Cryptographic Standards
- Passwords must meet a minimum length requirement of 8 characters.
- Hashing is performed using **Bcrypt** with a work factor of 12 rounds and cryptographically secure pseudorandom salt.
- Plaintext passwords are never logged, persisted in cache, or returned in API responses.

### 3. Rate Limiting Specifications
- `/api/v1/auth/login`: Limited to 15 authentication attempts per minute per IP address. Exceeding requests receive `429 Too Many Requests`.
- `/api/v1/scans`: Limited to 60 scan creation requests per minute per IP address.

### 4. Security Audit Logging
The `AuditLog` database entity maintains a persistent record of:
- `USER_REGISTER`, `USER_REGISTER_FAILED`
- `USER_LOGIN`, `USER_LOGIN_FAILED`, `USER_LOGIN_BLOCKED`
- `USER_LOGOUT`
- `SCAN_INITIATED`, `SCAN_COMPLETED`
- `EXPORT_CSV`, `REPORT_DOWNLOAD`
- `ADMIN_USER_STATUS_CHANGE`, `ADMIN_USER_ROLE_CHANGE`

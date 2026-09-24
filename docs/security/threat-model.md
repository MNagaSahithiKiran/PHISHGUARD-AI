# Formal STRIDE Threat Model

## 1. System Scope & Protected Assets
PhishGuard AI analyzes untrusted external web targets submitted by end users and SOC analysts.
Protected Assets:
1. **Host Infrastructure & Internal Network**: Preventing SSRF, RCE, or container breakout from untrusted websites.
2. **User & Analyst Accounts**: Password hashes, JWT tokens, RBAC roles.
3. **Database Records**: Scans, threat indicators, audit logs, and reports.
4. **Machine Learning Model Artifacts**: Pre-trained weights for URL Random Forest, MobileNetV2, and Fusion meta-classifiers.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Potential Threat Vector | Mitigating Defensive Controls | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker forging JWT access tokens to impersonate administrators. | Cryptographic HMAC-SHA256 signing with secret key validation; expired token rejection; fail-fast 32-char key enforcement. | Low (Secret key security dependent on hosting environment). |
| **Tampering** | Attacker modifying scan results or threat indicators in transit. | HTTPS / TLS 1.3 encryption; non-root database permissions; immutable foreign key constraints. | Negligible. |
| **Repudiation** | Analyst denies performing actions (e.g. user deletion or data export). | Tamper-resistant append-only `AuditLog` table stamped with timestamps, client IP, actor user_id, and correlation ID. | Low. |
| **Information Disclosure** | Stack traces, database strings, or private subnet IPs leaked in error messages. | Global exception handler sanitizes errors in production; structured JSON logging redacts sensitive keys; strict CSP and security headers. | Low. |
| **Denial of Service** | Resource exhaustion via massive concurrent scans or giant HTTP payload downloads. | Granular rate limiting (HTTP 429); `MAX_CONTENT_LENGTH_BYTES` (10MB limit, HTTP 413); connection/read timeouts; container CPU/memory quotas. | Low (Volumetric DDoS requires upstream Cloudflare / AWS Shield). |
| **Elevation of Privilege** | Normal user elevating role to administrator via manipulated profile update. | Explicit Pydantic validation prevents role modification on self-profile endpoints; role assignment strictly restricted to verified admin users. | Negligible. |
| **SSRF / Malicious Target** | Attacker submits `169.254.169.254` or `127.0.0.1` to access cloud metadata or local services. | Pre-flight DNS resolution checking against RFC 1918, link-local, loopback, and cloud metadata blocks; redirect re-validation. | Low (DNS rebinding mitigated by pinning resolved IP addresses). |

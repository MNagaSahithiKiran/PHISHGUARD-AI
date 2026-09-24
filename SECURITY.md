# Security Policy — PhishGuard AI

## 1. Supported Versions

Security updates and critical patches are actively provided for the following releases:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

---

## 2. Reporting a Vulnerability

The PhishGuard AI project takes system security and safe analysis seriously. If you discover a vulnerability, misconfiguration, or security risk:

1. **Do NOT open a public GitHub issue.**
2. Send an email to the security response team at **`security@phishguard.ai`** (or contact the repository maintainer directly through private GitHub security advisories).
3. Include the following details:
   - Type of vulnerability (e.g., SSRF bypass, IDOR, SQL injection, RCE, secret exposure).
   - Step-by-step instructions or proof-of-concept (PoC) to reproduce the issue.
   - Affected component(s): backend API, browser extension, or ML pipeline.
   - Potential impact of the vulnerability.

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.

---

## 3. Core Security Architecture & Guardrails

### Server-Side Request Forgery (SSRF) Protection
PhishGuard AI analyzes arbitrary untrusted URLs submitted by users. To prevent attackers from using the scanner as a proxy against internal networks, cloud metadata services, or intranet resources:
- Every target URL is validated before connection via `validate_and_sanitize_url()` and `SSRFGuard`.
- Direct IP addresses and resolved hostnames are checked against RFC 1918 private ranges, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and AWS/GCP/Azure cloud metadata endpoints (`169.254.169.254`).
- Connections to internal hostnames or addresses raise `SecurityValidationError` and are immediately aborted.

### Secret Management & Zero-Leakage Policy
- No real API keys, cryptographic tokens, or database passwords may ever be stored in the repository.
- Development uses `.env.example` placeholder files.
- Automated secret scanning scripts (`backend/scripts/scan_secrets.py`) run in CI/CD on every push to detect and block credentials before merge.

### Browser Extension Privacy & Security
- Minimal Manifest V3 permissions: `activeTab`, `storage`, `notifications`.
- No access to browsing history, cookies, or user credentials.
- The extension **never captures passwords or form inputs**.
- Communication with the backend uses TLS encryption only.

### Passive Multi-Modal Analysis
- HTML/DOM inspection is strictly passive. JavaScript is parsed statically via AST or BeautifulSoup without client-side execution during HTTP fetches.
- Sandboxed headless browser environments (Playwright) are isolated and execute with restricted capabilities.

# PHISHGUARD AI — Website Intelligence Engine Architecture

## 1. System Overview
The Website Intelligence Engine of **PhishGuard AI** (*"Detect. Explain. Protect."*) provides safe, controlled intake and multi-vector structural analysis of untrusted target websites. It bridges static URL lexical detection (Phase 2) with rich DOM, form, script, iframe, external resource, and HTTP header telemetry (Phase 3).

```
[ Client / Browser Extension / API User ]
                   │
                   ▼
       [ POST /api/v1/analyze ]
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│               Security & SSRF Guard Layer               │
│  - Scheme Validation (HTTP/HTTPS only)                 │
│  - DNS Resolution & Private Subnet Check               │
│  - Loopback / Cloud Metadata (169.254.169.254) Blocks  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│           Controlled HTTP Fetch Engine                 │
│  - 5MB Streaming Size Cap (Avoid Memory Exhaustion)   │
│  - Max 5 Redirect Hops (Hop-by-hop SSRF validation)    │
│  - Connection Timeout: 5s, Total Timeout: 10s          │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│           Multi-Vector Passive Analyzers               │
│  ├─ Redirect Analyzer (Downgrade/cross-domain hops)    │
│  ├─ HTML / Document Analyzer (Title, meta tags)       │
│  ├─ DOM Analyzer (Depth, node count, text ratio)      │
│  ├─ Form Analyzer (Credential harvesting targets)     │
│  ├─ Link Analyzer (Dispersion, null anchor ratio)     │
│  ├─ Script Analyzer (External domains, inline bytes)  │
│  ├─ Iframe Analyzer (Hidden frames, fullpage overlay) │
│  ├─ Resource Analyzer (External assets, mixed content)│
│  └─ Security Header Analyzer (HSTS, CSP, XFO, XCTO)   │
└──────────────────────────┬─────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌─────────────────────────┐   ┌──────────────────────────┐
│  Evidence Service       │   │  Feature Extractor       │
│  (Factual, Auditable)   │   │  (48 Numeric Features)   │
└───────────┬─────────────┘   └───────────┬──────────────┘
            │                             │
            └──────────────┬──────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│            Dual-Model Prediction Status Layer          │
│  ├─ URL Model (Phase 2 Random Forest: Genuine Pred)    │
│  └─ Website Model (Status: "not_available" / Phase 4)  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│          Database Persistence & API Output             │
│  ├─ scans table                                        │
│  ├─ website_analyses table                             │
│  ├─ website_redirect_hops table                        │
│  └─ website_evidence table                             │
└────────────────────────────────────────────────────────┘
```

## 2. Security Boundaries & Defensive Constraints
1. **Untrusted Target Paradigm**: All fetched content is considered malicious. The backend **never** evaluates JavaScript, executes client scripts, or executes arbitrary DOM manipulations.
2. **Strict Form Safety**: Forms are passively inspected for `<input type="password">` and cross-domain action destinations. The engine **never** submits forms or transmits simulated credentials.
3. **Hop-by-Hop Redirect Interception**: Default library redirect following is disabled (`follow_redirects=False`). Each intermediate HTTP 3xx response has its `Location` header checked through the SSRF Guard before establishing a new socket.

## 3. Database Schema Extensions
- `website_analyses`: Primary table capturing HTTP telemetry, DOM metrics, tag frequencies, form counts, link ratios, script metrics, and security header evaluations.
- `website_redirect_hops`: Records every individual redirect hop with source URL, target URL, and status code.
- `website_evidence`: Structured findings containing `category`, `severity` (info, low, medium, high, critical), `title`, `detail`, and `recommendation`.

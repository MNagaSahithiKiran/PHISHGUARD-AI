# Data Integrity & Reproducibility Audit Report

**Product:** PhishGuard AI  
**Scope:** Project-Wide Pipeline Data Integrity, Model Determinism, and Service Lineage  
**Status:** ALL INTEGRITY CONTROLS VERIFIED & PASSING

---

## 1. Audit Executive Summary

During production readiness testing, an end-to-end data integrity audit was conducted across the backend, ML pipeline, database schema, and frontend SOC dashboard. The objective was to eliminate any non-deterministic outputs, eradicate synthetic fallbacks, verify model artifact authenticity, and ensure complete isolation between scan executions.

---

## 2. Issues Identified, Root Causes & Remediation Matrix

| ID | Issue Description | Root Cause | Severity | Remediation Implemented | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | Cross-scan result contamination on `/intelligence/{scan_id}` | Fallback query matched on URL when fusion record was absent (`WHERE url = :url ORDER BY created_at DESC LIMIT 1`) | **CRITICAL** | Removed fallback query completely. Endpoint returns strict `404 Not Found` if scan has no fusion record. | **RESOLVED & VERIFIED** |
| **AUD-02** | Synthetic DOM probability on fetch failure | `fusion_service.py` computed `-2.2` logit even when website fetch failed | **HIGH** | Added explicit guard: when `http_err` occurs, `p_website = None`, status is `failed`, modality marked missing. | **RESOLVED & VERIFIED** |
| **AUD-03** | Lack of explicit URL identity columns | `Scan` table stored `url`, `normalized_url`, `canonical_url`, but lacked dedicated `final_url` and `redirect_chain` | **MEDIUM** | Added `final_url` and `redirect_chain` columns to DB schema, ORM model, and API schemas. | **RESOLVED & VERIFIED** |
| **AUD-04** | Bare hostnames and malformed inputs accepted | `validate_and_sanitize_url` prepended `https://` to bare words like `abc` or `example` | **HIGH** | Added strict FQDN structure checks, label validation, credential rejection, and port range validation. | **RESOLVED & VERIFIED** |
| **AUD-05** | Nonexistent domain DNS failure misclassification | Domains failing DNS resolution were scored via lexical model alone without network context | **HIGH** | Added `NetworkAnalyzer.resolve_dns()`. Unresolvable domains trigger `DNS_RESOLUTION_FAILED` and `INSUFFICIENT_EVIDENCE`. | **RESOLVED & VERIFIED** |
| **AUD-06** | Unpopulated `DomainInformation` table | Schema contained `domain_information` table but it was never instantiated during scans | **MEDIUM** | Built `NetworkAnalyzer` to perform passive DNS, TLS, and RDAP queries, persisting real records. | **RESOLVED & VERIFIED** |
| **AUD-07** | ML Model artifact tamper vulnerability | Joblib models loaded without checksum validation against metadata | **HIGH** | Computed and registered SHA-256 hashes in `model_metadata.json`; `ModelLoader` validates at load time. | **RESOLVED & VERIFIED** |
| **AUD-08** | Silent localhost fallback in production frontend | `getApiBaseUrl()` fell back to `http://localhost:8080` even under production builds | **MEDIUM** | Guarded by `import.meta.env.PROD`; displays `API CONFIGURATION REQUIRED` if variable omitted. | **RESOLVED & VERIFIED** |

---

## 3. Verification Test Evidence

1. **Model Loader Hash Verification**:
   - `random_forest.joblib` SHA-256: `7cbd005396e23872a0f67e0ddb9b30fe3fffe742f91b57956877352fbe598d49` (Verified matching)
   - `preprocessor.joblib` SHA-256: `b946212ee190b813c48368592a006c241365aa0b5dbdb7db155d402b93d51efd` (Verified matching)
2. **Backend Pytest Suite**: 86 / 86 tests passed (100% pass rate).
3. **Browser Extension Vitest Suite**: 21 / 21 tests passed (100% pass rate).
4. **Frontend Production Build**: `npm run build` completed cleanly without errors.
5. **Docker Compose Configuration**: `docker compose config` passed validation.

# External Threat Intelligence & Verification Services Documentation

**Product:** PhishGuard AI  
**Subsystem:** Threat Intelligence & External Verification  
**Policy Version:** `risk_policy_v1`

---

## 1. Overview & Data Integrity Principle

PhishGuard AI interfaces with third-party threat intelligence engines, reputation databases, and search indexes to enrich local machine learning classifications.

To ensure academic and production data integrity:
- **Zero Mock Data in Production**: PhishGuard AI never simulates external service responses, never invents threat scores, and never hardcodes fake Google check results.
- **Explicit Missing States**: If an API key is omitted, the service returns `NOT_CONFIGURED`. If an external endpoint times out or returns an error, the service returns `NOT_AVAILABLE` or `FAILED`.
- **Ledger Persistence**: Every external probe records an immutable `ScanEvidence` entry containing the provider name, timestamp, observed status, confidence, and SHA-256 evidence fingerprint.

---

## 2. Integrated External Providers

| Provider | Evidence Type | Purpose | Configuration Keys |
| :--- | :--- | :--- | :--- |
| **Google Safe Browsing (v4)** | `threat_reputation` | Query malware, social engineering, and unwanted software lists | `GOOGLE_SAFE_BROWSING_API_KEY` |
| **VirusTotal API (v3)** | `multi_engine_scan` | Aggregate 70+ antivirus scanners and domain categorization feeds | `VIRUSTOTAL_API_KEY` |
| **Google Custom Search** | `search_presence` | Index presence verification for registered domain | `GOOGLE_SEARCH_API_KEY`<br>`GOOGLE_SEARCH_ENGINE_ID` |
| **PhishTank & OpenPhish** | `community_feed` | Passive lookup against verified open-source phishing databases | Built-in offline feed with live update support |
| **RDAP (rdap.org)** | `domain_registration` | Official registrar, creation date, expiration, domain age | Public RDAP (no API key required) |

---

## 3. Provider Specifications & Status Behaviors

### 3.1 Google Safe Browsing
- **Endpoint**: `https://safebrowsing.googleapis.com/v4/threatMatches:find`
- **Statuses**:
  - `THREAT_MATCH`: Domain or URL is flagged in Google's threat database (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE).
  - `NO_MATCH`: URL verified by Google Safe Browsing and no threat detected.
  - `NOT_CONFIGURED`: `GOOGLE_SAFE_BROWSING_API_KEY` is not present in runtime environment.
  - `FAILED`: Network timeout or HTTP error received from Google API.

### 3.2 VirusTotal API v3
- **Endpoint**: `https://www.virustotal.com/api/v3/urls/{id}`
- **Statuses**:
  - `THREAT_MATCH`: One or more security vendors classify the URL/domain as malicious or phishing.
  - `NO_MATCH`: Zero vendors flagged the URL.
  - `NOT_CONFIGURED`: `VIRUSTOTAL_API_KEY` is omitted.
  - `FAILED`: Quota limit exceeded or network connection failure.

### 3.3 Google Custom Search Engine (CSE)
- **Endpoint**: `https://www.googleapis.com/customsearch/v1`
- **Purpose**: Verifies whether a domain possesses an established search footprint or is an unindexed throwaway domain.
- **Statuses**:
  - `CONFIRMED_RESULT`: Query for domain returns indexed search results matching the brand or domain.
  - `NO_RESULT`: Search engine returned zero matching entries for the query.
  - `NOT_CONFIGURED`: Keys are blank.
  - `FAILED`: HTTP request failure.
- **Commercial Caveat**: Google Search indexing reflects SEO and public visibility, not cryptographic safety. An indexed site may still be compromised, and a newly registered legitimate site may not yet be indexed. The Decision Policy treats search presence strictly as a corroborating signal, never as an absolute exemption.

### 3.4 Registration Data Access Protocol (RDAP)
- **Endpoint**: `https://rdap.org/domain/{domain}`
- **Purpose**: Retrieves official ICANN registration metadata without third-party scraping.
- **Extracted Fields**:
  - `registrar`: Official registrar entity name.
  - `creation_date`: Registration timestamp.
  - `expiration_date`: Domain expiration timestamp.
  - `domain_age_days`: `(now - creation_date).days`.
  - `nameservers`: Authoritative DNS nameservers.
- **Statuses**:
  - `RECORD_FOUND`: Registration record parsed successfully.
  - `NOT_AVAILABLE`: TLD or domain is not served by public RDAP, query timed out, or domain does not exist.

---

## 4. Environment Configuration Example

To enable live external providers, supply valid keys in `.env`:

```env
# Optional Threat Intelligence API Keys
GOOGLE_SAFE_BROWSING_API_KEY="AIzaSyYourActualKeyHere"
VIRUSTOTAL_API_KEY="your_virustotal_api_v3_key"
GOOGLE_SEARCH_API_KEY="AIzaSyYourGoogleCseApiKey"
GOOGLE_SEARCH_ENGINE_ID="0123456789abcdef:example"
```

If these keys are left empty, PhishGuard AI gracefully operates in isolated offline mode:
- ML lexical model executes locally.
- DOM and HTML analyzers execute locally.
- Network DNS and TLS probes execute directly against the target host.
- External providers report `NOT_CONFIGURED` without errors or fake data.

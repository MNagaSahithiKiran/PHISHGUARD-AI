# Browser Extension Privacy Guarantees & Code Compliance

## 1. Executive Privacy Statement
**PhishGuard AI Sentinel** is designed around the core principle of **Confidential Defensive Security**. A security extension must protect user data from external adversaries without invading the user's private browser session.

---

## 2. Core Privacy Guarantees

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PHISHGUARD AI PRIVACY CHARTER                        │
├────────────────────────────────────────────────────────────────────────┤
│  ✓  Zero Password Harvesting                                           │
│  ✓  Zero Keystroke Logging                                             │
│  ✓  Zero Cookie or Session Interception                                │
│  ✓  Zero Browsing History Profiling                                    │
│  ✓  Zero Silent URL Harvesting                                         │
│  ✓  Client-Side TTL Caching                                            │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Zero Password Harvesting
* The content script does **NOT** query or attach event listeners to `<input type="password">` elements.
* Form values, text inputs, authentication tokens, and user credentials are completely unread and uncollected.
* Verified by automated security test: `tests/security-safety.test.ts`.

### 2.2 Zero Keystroke Logging
* The extension contains **zero** event listeners for keyboard interactions (`keydown`, `keypress`, `keyup`).
* The extension cannot detect or log what users type into search bars, input forms, or web editors.

### 2.3 Zero Cookie Snooping
* The extension does not request the `cookies` permission.
* The content script and background worker have **no access** to `document.cookie`, HTTP cookies, session tokens, or local storage belonging to visited websites.

### 2.4 Zero Browsing History Profiling
* The extension does not request the `history` or `tabs` permissions.
* The extension cannot enumerate previously visited pages or generate browsing interest profiles.
* Scans are strictly initiated by explicit user interaction or controlled defensive alerts.

### 2.5 Server-Side SSRF & Network Isolation
* The extension transmits only the targeted URL string to the PhishGuard AI backend.
* The backend inspects the URL through an SSRF-hardened sandbox with private IP blocking, circuit breakers, and sandboxed headless rendering.

---

## 3. Automated Verification in CI/CD
These privacy guarantees are permanently enforced in the build pipeline via Vitest test suites:
* `tests/manifest.test.ts`: Verifies no unapproved permissions exist in `manifest.json`.
* `tests/security-safety.test.ts`: Scans all extension source files for forbidden DOM APIs, form scrapers, or keylogger patterns.

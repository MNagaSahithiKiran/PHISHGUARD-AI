# Browser Extension Architecture (Manifest V3)

## 1. Overview
The **PhishGuard AI Sentinel** is a high-performance Chromium browser extension built compliant with **Manifest V3**. It empowers users to inspect visited websites on-demand against PhishGuard AI's multi-modal intelligence pipeline directly from the browser toolbar.

---

## 2. Architecture Diagram

```mermaid
flowchart TD
    User([User in Chrome / Edge]) -->|Clicks PhishGuard Icon| PopupUI[Popup UI (React 18)]
    PopupUI -->|Queries activeTab| ChromeTabs[chrome.tabs API]
    ChromeTabs -->|Active URL| URLValidator[URL Validator & Sanitizer]
    
    URLValidator -->|Scheme Check| SchemeDecision{Valid Scheme?}
    SchemeDecision -->|No: chrome://, about:, file://| UnsupportedAlert[Unsupported Alert Banner]
    SchemeDecision -->|Yes: http://, https://| CacheCheck{In Cache & Valid TTL?}
    
    CacheCheck -->|Yes: Hit| RenderResults[Render Risk Score & Evidence]
    CacheCheck -->|No: Miss| BackgroundWorker[Service Worker (service-worker.js)]
    
    BackgroundWorker -->|POST /api/v1/intelligence/analyze| BackendAPI[(PhishGuard AI Backend)]
    BackendAPI -->|Multi-Modal Assessment| BackgroundWorker
    
    BackgroundWorker -->|Update Badge: !, ?, ✓| ChromeAction[chrome.action.setBadgeText]
    BackgroundWorker -->|Store Result (5m TTL)| LocalCache[ResultCache]
    BackgroundWorker -->|ScanResultData| PopupUI
    
    PopupUI -->|If PHISHING| ContentScript[Content Script: Warning Banner]
    PopupUI -->|Deep Link| WebPlatform[SOC Web Dashboard / PDF Report]
```

---

## 3. Core Components

### 3.1 Manifest V3 Declaration (`manifest.json`)
* Declares `manifest_version: 3`.
* Requests minimal permissions: `activeTab`, `storage`, `notifications`.
* Explicitly omits invasive permissions (`<all_urls>`, `cookies`, `webRequest`, `history`).
* Content Security Policy restricted strictly to `'self'`.

### 3.2 Popup Interface (`src/popup/`)
* **Technology**: React 18, TypeScript, Tailwind CSS, Lucide icons.
* **Active Tab Resolution**: Queries `chrome.tabs.query({ active: true, currentWindow: true })`.
* **Real-time Pipeline Stepper**: Visual stages for `Preparing Target`, `URL Intelligence`, `DOM & Network`, `Computer Vision`, and `Multi-Modal Fusion`.
* **Continuous Risk Meter**: Continuous $0-100$ gauge with color zones (`LEGITIMATE` green, `SUSPICIOUS` amber, `PHISHING` crimson).
* **Calibrated Probabilities**: Displays authentic calculated phishing probabilities (e.g. $94.2\%$).
* **Factual Evidence Drawer**: Explains detected security anomalies without fabrication.
* **Deep Links**: Direct links to SOC Web Platform scan detail (`http://localhost:5173/scans/:id`) and PDF report download (`http://localhost:8000/api/v1/scans/:id/report.pdf`).

### 3.3 Background Service Worker (`src/background/service-worker.ts`)
* Event-driven background worker complying with Manifest V3 short-lived worker lifecycle.
* Intercepts `ANALYZE_URL`, `CLEAR_CACHE`, and `OPEN_OPTIONS` messages.
* Dynamically updates the browser extension badge:
  * `!` with crimson background for `PHISHING`.
  * `?` with amber background for `SUSPICIOUS`.
  * `✓` with emerald background for `LEGITIMATE`.

### 3.4 Defensive Content Script (`src/content/content-script.ts`)
* Injected at `document_idle` on visited HTTP/HTTPS tabs.
* **Strictly defensive**: Only listens for `SHOW_THREAT_WARNING` from the extension when an active scan confirms high-risk phishing.
* Renders an un-intrusive, dismissible top banner warning the user not to input credentials or submit forms.
* Sanitizes domain and context inputs via HTML escaping to prevent XSS injection.

### 3.5 Options & Configuration (`src/options/`)
* Configurable API base URL (defaults to `http://localhost:8000/api/v1`).
* Endpoint health test button to verify server connectivity.
* In-page warning banner preference toggle.
* Scan cache TTL slider (1 to 60 minutes, default 5 minutes).
* Cache memory status and one-click "Clear Cache" button.
* Explicit privacy & safety declaration.

---

## 4. Caching & Performance
* In-memory `ResultCache` stores scan results keyed by normalized domain and path.
* Normalizes URLs (case insensitivity, query parameters, trailing slash stripping).
* Default TTL: 5 minutes.
* Mitigates duplicate API traffic when user re-opens the popup on the same tab.

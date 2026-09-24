# Browser Extension Security Policy & Hardening

## 1. Principles of Defensive Design
The **PhishGuard AI Sentinel** extension is engineered as a defensive cybersecurity utility. It adheres to strict zero-trust and least-privilege standards to ensure that the security tool itself never becomes a vector for compromise.

---

## 2. Least Privilege Permission Model

| Permission | Justification & Scope | Security Risk Mitigation |
| :--- | :--- | :--- |
| `activeTab` | Read the URL and title of the currently focused tab **only when the user invokes the extension**. | Does **NOT** grant background observation of all user browsing. Extension has zero access to non-active tabs. |
| `storage` | Stores user configuration (API URL, TTL, banner preferences) locally in `chrome.storage.local`. | Sandboxed to the extension ID; inaccessible to external websites or third parties. |
| `notifications` | Allows desktop notifications when a background scan detects active credential harvesting. | Low risk; user can toggle off at any time. |

### Forbidden Permissions Matrix
To preserve user trust, PhishGuard AI **explicitly rejects** the following high-risk Chrome permissions:
* `cookies`: Rejected. Zero reading, writing, or inspection of HTTP cookies or session tokens.
* `webRequest` / `webRequestBlocking`: Rejected. Extension never inspects, modifies, or intercepts raw network packets or HTTP payloads.
* `history`: Rejected. Browsing history is never collected, queried, or analyzed.
* `debugger`: Rejected. Zero remote debugging or DOM inspection hooks.
* `clipboardRead`: Rejected. Clipboard contents are completely inaccessible.
* `<all_urls>` host permissions: Rejected. No background carte-blanche domain observation.

---

## 3. Content Security Policy (CSP)
PhishGuard AI implements a strict Manifest V3 Content Security Policy:

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self';"
}
```

* **No Unsafe Eval**: Evaluated JavaScript (`eval()`, `new Function()`, `setTimeout(string)`) is strictly disallowed.
* **No Remote Scripts**: Scripts from CDNs or external origins cannot be executed inside the extension context.
* **Hermetic Bundling**: All scripts (React, Lucide, Tailwind styles) are compiled and packaged into the local distribution bundle (`dist/`).

---

## 4. Content Script Isolation & DOM Sanitization
* The defensive content script runs in an isolated world and communicates exclusively via message passing (`chrome.runtime.onMessage`).
* In-page alert banners never interpolate unsanitized strings directly into HTML templates.
* All dynamic fields (e.g. domain names, risk scores) are sanitized via DOM text encoding:
  ```ts
  function escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
  }
  ```

---

## 5. Protocol & Internal Page Protection
The extension rigorously blocks execution against internal or privileged browser URLs:
* `chrome://*` and `chrome-extension://*`
* `edge://*`
* `about:*` (including `about:blank`, `about:config`)
* `file:///*` (local filesystem)
* `data:*` and `javascript:*`

These pages immediately trigger an `unsupported` state and abort network requests, preventing cross-origin data leakage or browser internal inspection.

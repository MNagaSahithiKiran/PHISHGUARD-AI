# PhishGuard AI - Sentinel Browser Extension

The PhishGuard AI Sentinel extension delivers real-time anti-phishing inspection for Chromium-based web browsers (Chrome, Brave, Edge).

## Architecture (Manifest V3)

- **Service Worker (`src/background/index.js`)**: Communicates with the PhishGuard AI FastAPI backend API over asynchronous message passing.
- **Popup Inspector (`src/popup/`)**: Compact HUD displaying tab safety posture and triggering instant scan requests.
- **Passive Content Guard (`src/content/content.js`)**: Sandboxed, read-only observer.

## Installation Instructions

1. Open your browser and navigate to `chrome://extensions/` (or `brave://extensions/`).
2. Toggle on **Developer mode** in the upper-right corner.
3. Click **Load unpacked**.
4. Select the directory: `phishguard-ai/browser-extension/`.
5. Ensure the backend API is running at `http://localhost:8000`.

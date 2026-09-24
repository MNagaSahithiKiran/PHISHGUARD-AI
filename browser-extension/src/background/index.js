// PhishGuard AI Background Service Worker (Manifest V3)
const BACKEND_API_BASE = "http://localhost:8000/api/v1";

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI Sentinel extension installed successfully.");
});

// Listener for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "CHECK_URL") {
    fetch(`${BACKEND_API_BASE}/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: request.url })
    })
      .then(res => res.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true; // Keep message channel open for async response
  }
});

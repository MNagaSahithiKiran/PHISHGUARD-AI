document.addEventListener("DOMContentLoaded", async () => {
  const tabUrlEl = document.getElementById("tab-url");
  const statusTextEl = document.getElementById("status-text");
  const scanBtn = document.getElementById("scan-btn");

  let currentTabUrl = "";

  // Query active tab in current window
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      currentTabUrl = tab.url;
      tabUrlEl.textContent = currentTabUrl;
    } else {
      tabUrlEl.textContent = "Unable to read active tab URL";
      scanBtn.disabled = true;
    }
  } catch (err) {
    tabUrlEl.textContent = "Extension running outside tab context";
  }

  scanBtn.addEventListener("click", () => {
    if (!currentTabUrl) return;

    statusTextEl.textContent = "Submitting to PhishGuard Sentinel...";
    scanBtn.disabled = true;

    chrome.runtime.sendMessage(
      { action: "CHECK_URL", url: currentTabUrl },
      (response) => {
        scanBtn.disabled = false;
        if (response && response.success) {
          statusTextEl.textContent = `Queued (ID: ${response.data.scan_id.slice(0, 8)}...)`;
          statusTextEl.style.color = "#34d399";
        } else {
          statusTextEl.textContent = `Error: ${response ? response.error : "Failed to connect to API"}`;
          statusTextEl.style.color = "#f87171";
        }
      }
    );
  });
});

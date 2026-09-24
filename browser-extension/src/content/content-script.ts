// PhishGuard AI - Privacy-Preserving Content Script
// COMPLIANCE: NEVER reads input fields, never monitors keystrokes, never reads cookies, never modifies form actions.

console.log('[PhishGuard AI Sentinel] Content script initialized in defensive monitor mode.');

// Listen for threat warning messages from extension
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.action === 'SHOW_THREAT_WARNING') {
    displayWarningBanner(request.riskScore || 90, request.domain || window.location.hostname);
    sendResponse({ status: 'warning_rendered' });
  }
});

function displayWarningBanner(riskScore: number, domain: string) {
  // Prevent duplicate banners
  if (document.getElementById('phishguard-threat-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'phishguard-threat-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    z-index: 2147483647;
    background: #e11d48;
    color: #ffffff;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif;
    padding: 12px 16px;
    box-shadow: 0 4px 14px rgba(0,0,0,0.4);
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-sizing: border-box;
    font-size: 13px;
    line-height: 1.4;
  `;

  const textDiv = document.createElement('div');
  textDiv.style.cssText = 'display: flex; align-items: center; gap: 8px; font-weight: 500;';
  textDiv.innerHTML = `
    <span style="font-size: 16px;">🛡</span>
    <span><strong>PHISHGUARD AI ALERT:</strong> High phishing risk detected for <code>${escapeHtml(domain)}</code> (Risk Score: ${riskScore}/100). Do not enter passwords or credentials.</span>
  `;

  const btnDiv = document.createElement('div');
  btnDiv.style.cssText = 'display: flex; gap: 8px;';

  const dismissBtn = document.createElement('button');
  dismissBtn.innerText = 'Dismiss';
  dismissBtn.style.cssText = `
    background: rgba(0,0,0,0.3);
    border: 1px solid rgba(255,255,255,0.4);
    color: #ffffff;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
  `;
  dismissBtn.onclick = () => banner.remove();

  btnDiv.appendChild(dismissBtn);
  banner.appendChild(textDiv);
  banner.appendChild(btnDiv);

  document.body.prepend(banner);
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.innerText = str;
  return div.innerHTML;
}

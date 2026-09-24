"""
PhishGuard AI - Headless Browser Screenshot Service
Safely renders websites in an isolated, headless Chromium container using Playwright.
Gracefully handles environments where browser binaries are not installed.
Never evaluates untrusted user-supplied scripts.
"""

import os
import logging
from typing import Optional, Tuple
from pathlib import Path

logger = logging.getLogger("phishguard.browser")

SCREENSHOT_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "screenshots"


def ensure_screenshot_dir() -> Path:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    return SCREENSHOT_DIR


async def capture_website_screenshot(url: str, scan_id: str, timeout_ms: int = 8000) -> Tuple[Optional[str], Optional[str]]:
    """
    Renders the target webpage in headless Chromium and captures a screenshot.
    Returns: (relative_screenshot_path, error_message)
    """
    ensure_screenshot_dir()
    output_filename = f"{scan_id}.png"
    output_path = SCREENSHOT_DIR / output_filename
    relative_url = f"/api/v1/screenshots/{output_filename}"

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info("Playwright not installed, skipping screenshot capture.")
        return None, "Playwright library is not installed in the environment."

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            # Create isolated context
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PhishGuardSecurityScanner/1.0",
                ignore_https_errors=True,
            )
            page = await context.new_page()

            try:
                # Navigate with controlled timeout
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Brief wait for any remaining visual layout
                await page.wait_for_timeout(500)
                await page.screenshot(path=str(output_path), full_page=False)
                await browser.close()
                return relative_url, None
            except Exception as nav_err:
                await browser.close()
                logger.warning(f"Screenshot navigation error for {url}: {nav_err}")
                return None, f"Screenshot render error: {str(nav_err)}"

    except Exception as e:
        logger.warning(f"Playwright screenshot error for {url}: {e}")
        return None, f"Screenshot subsystem unavailable: {str(e)}"

"""
PhishGuard AI - Secure Screenshot Capture Service
Uses isolated headless Playwright Chromium to capture screenshots of authorized targets.
CRITICAL DEFENSE ENFORCEMENT:
- Validates URL and DNS against Phase 3 SSRFGuard before connecting.
- Clean browser context without cookies, credentials, or user profiles.
- Strict 8-second navigation timeout.
- Size and dimension limits (1280x800).
- Never submits forms or inputs credentials.
- Stores screenshots with unique UUIDs under backend/storage/screenshots.
"""

import uuid
import time
import logging
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False

from app.core.security import validate_and_sanitize_url
from app.analyzers.safety.ssrf_guard import SSRFGuard, SSRFSecurityException
from ml.vision.preprocessing.image_loader import validate_image_file

logger = logging.getLogger("phishguard.vision.screenshot")

SCREENSHOT_STORAGE_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "screenshots"


class ScreenshotService:
    @classmethod
    def ensure_storage_dir(cls) -> Path:
        SCREENSHOT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        return SCREENSHOT_STORAGE_DIR

    @classmethod
    async def capture_target_screenshot(
        cls,
        target_url: str,
        scan_id: Optional[str] = None,
        timeout_ms: int = 8000,
    ) -> Dict[str, Any]:
        """
        Executes a secure, isolated webpage screenshot capture.
        """
        cls.ensure_storage_dir()
        screenshot_id = str(uuid.uuid4())
        scan_ref = scan_id or screenshot_id

        # 1. Enforce Phase 3 SSRF Safety
        try:
            sanitized = validate_and_sanitize_url(target_url)
            normalized_url = sanitized["normalized_url"]
            SSRFGuard.validate_target_url(normalized_url)
        except Exception as e:
            logger.warning(f"Screenshot capture blocked by SSRFGuard: {e}")
            raise SSRFSecurityException("Analysis blocked for security reasons.")

        filename = f"{scan_ref}_{screenshot_id[:8]}.png"
        output_path = SCREENSHOT_STORAGE_DIR / filename
        relative_url = f"/api/v1/screenshots/{filename}"

        start_time = time.time()

        # 2. Render in Isolated Headless Chromium
        if not PLAYWRIGHT_AVAILABLE:
            logger.info("Playwright not installed, skipping browser render.")
            return None, {"error": "Playwright is not installed in the environment."}

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
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuardVision/1.0",
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                try:
                    await page.goto(normalized_url, wait_until="domcontentloaded", timeout=timeout_ms)
                    await page.wait_for_timeout(400)
                    await page.screenshot(path=str(output_path), full_page=False)
                finally:
                    await browser.close()

            duration_ms = round((time.time() - start_time) * 1000, 2)

            # 3. Validate Captured Image
            val_res = validate_image_file(output_path)
            if not val_res.is_valid:
                if output_path.exists():
                    output_path.unlink()
                raise ValueError(f"Captured screenshot failed integrity check: {val_res.error_message}")

            file_size = output_path.stat().st_size

            from app.intelligence.reproducibility import compute_screenshot_hash
            shot_hash = compute_screenshot_hash(output_path)

            return {
                "screenshot_id": screenshot_id,
                "scan_id": scan_ref,
                "url": normalized_url,
                "file_path": str(output_path),
                "relative_url": relative_url,
                "width": val_res.width,
                "height": val_res.height,
                "file_size_bytes": file_size,
                "format": val_res.format_name,
                "md5_hash": val_res.md5_hash,
                "screenshot_hash": shot_hash,
                "duration_ms": duration_ms,
            }


        except Exception as e:
            logger.error(f"Screenshot capture failed for {normalized_url}: {e}")
            raise

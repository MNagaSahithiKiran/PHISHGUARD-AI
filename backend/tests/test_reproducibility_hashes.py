"""
PhishGuard AI - Cryptographic Reproducibility Hash Tests
Verifies deterministic hashing of features, DOM snapshots, models, predictions,
and scan comparison diagnostics.
"""

import pytest
from app.core.security import normalize_url, validate_and_sanitize_url
from app.intelligence.reproducibility import (
    compute_url_feature_hash,
    compute_snapshot_hash,
    compute_screenshot_hash,
    compute_model_input_hash,
    compute_prediction_hash,
    detect_live_content_change,
    compare_scans,
)


def test_url_normalization_determinism():
    """Different raw representations of identical target URL must yield identical normalized URL."""
    url1 = "HTTPS://ChatGPT.COM:443/c/6ab3b859-af1c-83ee-9fee-5a18a379826c?b=2&a=1#section"
    url2 = "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c?a=1&b=2"
    
    norm1 = normalize_url(url1)
    norm2 = normalize_url(url2)
    
    assert norm1 == norm2
    assert norm1 == "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c?a=1&b=2"


def test_url_feature_hash_determinism():
    """Identical feature dictionary must produce identical SHA-256 hash."""
    features1 = {"url_length": 62, "entropy": 3.84, "dots": 1, "hyphens": 4}
    features2 = {"hyphens": 4, "dots": 1, "url_length": 62, "entropy": 3.84}  # different key order
    features3 = {"url_length": 63, "entropy": 3.84, "dots": 1, "hyphens": 4}  # different value

    h1 = compute_url_feature_hash(features1)
    h2 = compute_url_feature_hash(features2)
    h3 = compute_url_feature_hash(features3)

    assert len(h1) == 64
    assert h1 == h2
    assert h1 != h3


def test_snapshot_hash_volatility_stripping():
    """Dynamic CSRF tokens or nonces must be normalized so identical templates hash identically."""
    html_run1 = (
        '<html><head><input type="hidden" name="csrf_token" value="nonce_abc_123" /></head>'
        '<body><h1>Welcome to Portal</h1></body></html>'
    )
    html_run2 = (
        '<html><head><input type="hidden" name="csrf_token" value="nonce_xyz_999" /></head>'
        '<body><h1>Welcome to Portal</h1></body></html>'
    )
    html_modified = (
        '<html><head><input type="hidden" name="csrf_token" value="nonce_xyz_999" /></head>'
        '<body><h1>Welcome to Portal - ATTACK INJECTED</h1></body></html>'
    )

    h1 = compute_snapshot_hash(html_run1)
    h2 = compute_snapshot_hash(html_run2)
    h_mod = compute_snapshot_hash(html_modified)

    assert h1 == h2
    assert h1 != h_mod


def test_live_content_change_detection():
    """Detects when target website content has changed between scans."""
    snap_a = "a" * 64
    snap_b = "b" * 64

    changed, notice = detect_live_content_change(snap_a, snap_b)
    assert changed is True
    assert "Website snapshot differs" in notice

    changed_same, notice_same = detect_live_content_change(snap_a, snap_a)
    assert changed_same is False
    assert notice_same is None


def test_compare_scans_utility():
    """Validates full diagnostic comparison output between two scan objects."""
    scan_1 = {
        "id": "scan-1",
        "url": "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c",
        "normalized_url": "https://chatgpt.com/c/6ab3b859-af1c-83ee-9fee-5a18a379826c",
        "url_feature_hash": "feat_hash_123",
        "model_version": "1.0.0",
        "preprocessing_version": "1.0.0",
        "dom_snapshot_hash": "dom_hash_abc",
        "screenshot_hash": "screen_hash_xyz",
        "decision_policy_version": "1.0.0",
        "verdict": "suspicious",
        "risk_score": 28.5,
    }
    
    # Identical scan
    scan_2 = dict(scan_1, id="scan-2")
    comp = compare_scans(scan_1, scan_2)

    assert comp["is_reproducible"] is True
    assert comp["normalized_url"] == "SAME"
    assert comp["feature_hash"] == "SAME"
    assert comp["website_snapshot"] == "SAME"
    assert comp["prediction"] == "SAME"
    assert comp["risk_score"] == "SAME"
    assert "PERFECT DETERMINISTIC REPRODUCIBILITY" in comp["explanation"]

    # Scan with live content change
    scan_3 = dict(scan_1, id="scan-3", dom_snapshot_hash="dom_hash_DIFFERENT")
    comp_changed = compare_scans(scan_1, scan_3)
    assert comp_changed["live_content_changed"] is True
    assert comp_changed["website_snapshot"] == "DIFFERENT"
    assert "LIVE CONTENT CHANGED" in comp_changed["explanation"]

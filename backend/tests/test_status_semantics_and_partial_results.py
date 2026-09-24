"""
PhishGuard AI - Status Semantics & Partial Results Tests
Ensures pipeline distinguishes available, completed, failed, and not_available stages.
Guarantees unanalyzed modalities are never reported as 0.0 probability.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_fusion_without_visual_reports_clean_status(client):
    """
    When include_visual=False, visual modality must have status='not_available'
    and probability=None (never 0.0 fake float).
    """
    res = await client.post(
        "/api/v1/intelligence/analyze",
        json={"url": "https://wikipedia.org", "include_visual": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert "visual" in data["models"]
    visual_mod = data["models"]["visual"]
    
    assert visual_mod["status"] in ["not_available", "failed"]
    assert visual_mod.get("probability") is None
    assert "visual" not in data["modalities_used"]
    assert "visual" in data["missing_modalities"]


@pytest.mark.asyncio
async def test_compare_scans_endpoint(client):
    """
    Tests GET /api/v1/scans/compare returns side-by-side diagnostic comparison.
    """
    # Create scan 1
    res1 = await client.post(
        "/api/v1/intelligence/analyze",
        json={"url": "https://wikipedia.org", "include_visual": False},
    )
    assert res1.status_code == 200
    s1_id = res1.json()["scan_id"]

    # Create scan 2
    res2 = await client.post(
        "/api/v1/intelligence/analyze",
        json={"url": "https://wikipedia.org", "include_visual": False},
    )
    assert res2.status_code == 200
    s2_id = res2.json()["scan_id"]

    # Compare the two scans
    comp_res = await client.get(f"/api/v1/scans/compare?scan_id_1={s1_id}&scan_id_2={s2_id}")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    
    assert comp_data["normalized_url"] == "SAME"
    assert comp_data["feature_vector"] == "SAME"
    assert "is_reproducible" in comp_data
    assert "explanation" in comp_data

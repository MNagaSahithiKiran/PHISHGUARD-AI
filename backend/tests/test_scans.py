import pytest

@pytest.mark.asyncio
async def test_create_scan_queued(client):
    payload = {"url": "https://example.com/test-verify"}
    response = await client.post("/api/v1/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["url"] == "https://example.com/test-verify"
    assert data["status"] == "queued"
    assert data["message"] == "Scan created successfully"


@pytest.mark.asyncio
async def test_get_scan_detail(client):
    # Create scan first
    create_res = await client.post("/api/v1/scans", json={"url": "https://sub.testdomain.org/login"})
    assert create_res.status_code == 201
    scan_id = create_res.json()["scan_id"]

    # Retrieve scan detail
    detail_res = await client.get(f"/api/v1/scans/{scan_id}")
    assert detail_res.status_code == 200
    data = detail_res.json()
    assert data["id"] == scan_id
    assert data["status"] == "queued"
    assert data["domain"] == "testdomain.org"
    
    # Lexical features must be extracted
    assert data["url_features"] is not None
    assert data["url_features"]["count_dots"] >= 1
    assert data["url_features"]["entropy_score"] > 0
    
    # Scan result must be strictly unrated (zero fake predictions)
    assert data["scan_result"] is not None
    assert data["scan_result"]["verdict"] == "unrated"
    assert data["scan_result"]["confidence_score"] is None


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    response = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_scans_and_stats(client):
    # Create two scans
    await client.post("/api/v1/scans", json={"url": "https://example-one.com"})
    await client.post("/api/v1/scans", json={"url": "https://example-two.org"})

    # Check list endpoint
    list_res = await client.get("/api/v1/scans")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 2
    assert len(list_data["items"]) >= 2

    # Check stats endpoint
    stats_res = await client.get("/api/v1/scans/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_scans"] >= 2
    assert stats_data["queued_scans"] >= 2
    assert stats_data["phishing_detected"] == 0  # No fake detections

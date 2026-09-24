import pytest


@pytest.mark.asyncio
async def test_platform_analytics_threat_intel_and_transparency(client):
    # Create sample scan so data is available
    await client.post("/api/v1/scans", json={"url": "https://threat-sample.org/login"})

    # 1. Analytics overview
    res_analytics = await client.get("/api/v1/analytics/overview")
    assert res_analytics.status_code == 200
    data_a = res_analytics.json()
    assert "total_scans" in data_a
    assert data_a["total_scans"] >= 1
    assert "phishing_scans" in data_a
    assert "risk_distribution" in data_a
    assert len(data_a["risk_distribution"]) == 5

    # 2. Analytics trends
    res_trends = await client.get("/api/v1/analytics/trends?days=7")
    assert res_trends.status_code == 200
    data_t = res_trends.json()
    assert isinstance(data_t, list)
    assert len(data_t) == 7

    # 3. Threat intelligence indicators
    res_ind = await client.get("/api/v1/threat-intel/indicators")
    assert res_ind.status_code == 200
    data_ind = res_ind.json()
    assert "top_indicators" in data_ind
    assert "severity_breakdown" in data_ind

    # 4. Threat intelligence observed domains
    res_dom = await client.get("/api/v1/threat-intel/domains")
    assert res_dom.status_code == 200
    assert isinstance(res_dom.json(), list)

    # 5. Model Transparency cards
    res_models = await client.get("/api/v1/models/transparency")
    assert res_models.status_code == 200
    data_m = res_models.json()
    assert "registered_models" in data_m
    assert len(data_m["registered_models"]) == 4

    # Verify all models contain explainability and provenance
    for card in data_m["registered_models"]:
        assert "architecture" in card
        assert "training_data_provenance" in card
        assert "metrics" in card
        assert len(card["explainability_methods"]) > 0


@pytest.mark.asyncio
async def test_notifications_lifecycle(client):
    # Register user for notifications
    user_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "notify_test@phishguard.ai",
            "password": "Password12345!",
            "full_name": "Notify Tester"
        }
    )
    token = user_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Query notifications
    res_n = await client.get("/api/v1/notifications", headers=auth_headers)
    assert res_n.status_code == 200
    assert isinstance(res_n.json(), list)

    # Mark all read
    res_mark = await client.post("/api/v1/notifications/mark-all-read", headers=auth_headers)
    assert res_mark.status_code == 200
    assert res_mark.json()["status"] == "ok"

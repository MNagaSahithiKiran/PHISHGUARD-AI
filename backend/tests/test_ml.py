import pytest

@pytest.mark.asyncio
async def test_ml_predict_endpoint(client):
    payload = {"url": "https://www.google.com"}
    response = await client.post("/api/v1/ml/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] in ["legitimate", "phishing"]
    assert data["label"] in [0, 1]
    assert 0.0 <= data["probability"] <= 1.0
    assert 0.0 <= data["confidence"] <= 100.0
    assert "model_version" in data
    assert "feature_version" in data
    assert data["inference_time_ms"] > 0
    assert data["top_explanations"] is not None
    assert len(data["top_explanations"]) > 0


@pytest.mark.asyncio
async def test_ml_predict_ssrf_blocked(client):
    payload = {"url": "http://127.0.0.1:8000/admin"}
    response = await client.post("/api/v1/ml/predict", json=payload)
    assert response.status_code == 400
    assert "SSRF Protection" in response.json()["detail"]


@pytest.mark.asyncio
async def test_ml_models_status_endpoint(client):
    response = await client.get("/api/v1/ml/models")
    assert response.status_code == 200
    data = response.json()
    assert data["is_trained"] is True
    assert data["selected_model"] == "Random Forest"
    assert len(data["benchmarks"]) >= 4
    # Verify benchmark structure
    first = data["benchmarks"][0]
    assert "accuracy" in first
    assert "f1" in first
    assert "precision" in first
    assert "recall" in first

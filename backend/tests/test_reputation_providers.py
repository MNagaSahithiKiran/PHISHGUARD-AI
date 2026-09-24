import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx

from app.services.reputation.schemas import ReputationStatus
from app.services.reputation.google_search import GoogleSearchProvider
from app.services.reputation.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.reputation.virustotal import VirusTotalProvider
from app.services.reputation.phishing_feeds import PhishingFeedProvider
from app.services.reputation.reputation_service import ReputationService


@pytest.mark.asyncio
async def test_google_search_unconfigured():
    provider = GoogleSearchProvider()
    provider.api_key = None
    provider.engine_id = None

    res = await provider.query("https://example.com", "example.com")
    assert res.status == ReputationStatus.NOT_CONFIGURED
    assert res.is_threat is None
    assert "not configured" in res.summary.lower()


@pytest.mark.asyncio
async def test_google_search_no_results():
    provider = GoogleSearchProvider()
    provider.api_key = "test_key"
    provider.engine_id = "test_engine"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [],
        "searchInformation": {"totalResults": "0"}
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.query("https://example.com", "example.com")
        assert res.status == ReputationStatus.NO_RESULT
        assert res.is_threat is None
        assert "No matching Google Search result was returned" in res.summary


@pytest.mark.asyncio
async def test_google_search_confirmed_results():
    provider = GoogleSearchProvider()
    provider.api_key = "test_key"
    provider.engine_id = "test_engine"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {"title": "Example Domain", "link": "https://example.com", "snippet": "Example Domain description"}
        ],
        "searchInformation": {"totalResults": "1"}
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.query("https://example.com", "example.com")
        assert res.status == ReputationStatus.CONFIRMED_RESULT
        assert res.is_threat is False
        assert len(res.details["results"]) == 1
        assert res.details["results"][0]["title"] == "Example Domain"


@pytest.mark.asyncio
async def test_google_safe_browsing_unconfigured():
    provider = GoogleSafeBrowsingProvider()
    provider.api_key = None

    res = await provider.query("https://example.com", "example.com")
    assert res.status == ReputationStatus.NOT_CONFIGURED
    assert res.is_threat is None


@pytest.mark.asyncio
async def test_google_safe_browsing_threat_match():
    provider = GoogleSafeBrowsingProvider()
    provider.api_key = "test_sb_key"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {"threatType": "MALWARE", "platformType": "ANY_PLATFORM"}
        ]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.query("https://malware.example.com", "malware.example.com")
        assert res.status == ReputationStatus.THREAT_MATCH
        assert res.is_threat is True
        assert "MALWARE" in res.summary


@pytest.mark.asyncio
async def test_virustotal_unconfigured():
    provider = VirusTotalProvider()
    provider.api_key = None

    res = await provider.query("https://example.com", "example.com")
    assert res.status == ReputationStatus.NOT_CONFIGURED
    assert res.is_threat is None


@pytest.mark.asyncio
async def test_virustotal_threat_match():
    provider = VirusTotalProvider()
    provider.api_key = "test_vt_key"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10
                }
            }
        }
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.query("https://evil.example.com", "evil.example.com")
        assert res.status == ReputationStatus.THREAT_MATCH
        assert res.is_threat is True
        assert "8 engine flags" in res.summary


@pytest.mark.asyncio
async def test_virustotal_clean():
    provider = VirusTotalProvider()
    provider.api_key = "test_vt_key"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5
                }
            }
        }
    }

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.query("https://google.com", "google.com")
        assert res.status == ReputationStatus.SAFE
        assert res.is_threat is False


@pytest.mark.asyncio
async def test_phishing_feeds_match():
    provider = PhishingFeedProvider()
    provider._cached_urls = {"http://phish-login.com", "evil-login.net"}

    res = await provider.query("http://phish-login.com/login", "phish-login.com")
    assert res.status == ReputationStatus.THREAT_MATCH
    assert res.is_threat is True


@pytest.mark.asyncio
async def test_reputation_service_orchestration():
    service = ReputationService.get_instance()
    summary = await service.check_reputation("https://example.com", "example.com")
    assert summary.providers_queried == 4
    assert len(summary.evidence_ledger) == 4
    for item in summary.evidence_ledger:
        assert item.evidence_hash is not None
        assert len(item.evidence_hash) == 64

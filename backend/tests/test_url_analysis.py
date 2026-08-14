from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from routers import url as url_router
from services import virustotal
from services.url_service import extract_url_information, get_url_identifier
from services.url_validator import normalize_url


def make_vt_result(status="found"):
    if status != "found":
        return {
            "status": status,
            "permalink": "https://www.virustotal.com/gui/url/test",
        }

    return {
        "status": "found",
        "detections": 1,
        "malicious_detections": 1,
        "suspicious_detections": 0,
        "total_engines": 3,
        "usable_engines": 3,
        "unusable_engines": 0,
        "unusable_breakdown": {},
        "threat_label": None,
        "threat_categories": [
            {
                "engine": "Test Engine",
                "value": "phishing",
            }
        ],
        "flagged_engines": [
            {
                "engine": "Test Engine",
                "category": "malicious",
                "result": "phishing",
            }
        ],
        "first_seen": None,
        "last_analysis": 1715000000,
        "meaningful_name": "https://example.com/login",
        "associated_names": [],
        "file_type": "URL",
        "file_size": None,
        "tags": [],
        "reputation": -1,
        "community_reputation": -1,
        "times_submitted": 4,
        "permalink": "https://www.virustotal.com/gui/url/test",
        "raw": {},
    }


def test_normalize_url_adds_https():
    assert normalize_url("google.com") == "https://google.com"


def test_normalize_url_rejects_invalid_values():
    with pytest.raises(ValueError):
        normalize_url("")

    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")

    with pytest.raises(ValueError):
        normalize_url("https://exa mple.com")


def test_url_information_extraction():
    result = extract_url_information(
        "https://example.com:8443/login?q=1#section"
    )

    assert result["protocol"] == "https"
    assert result["host"] == "example.com"
    assert result["path"] == "/login"
    assert result["query"] == "q=1"
    assert result["fragment"] == "section"
    assert result["port"] == 8443
    assert result["domain"] == "example.com"
    assert result["url_length"] > 0


def test_url_identifier_is_urlsafe_base64_without_padding():
    assert get_url_identifier("https://example.com") == "aHR0cHM6Ly9leGFtcGxlLmNvbQ"


@pytest.mark.asyncio
async def test_url_analysis_valid_guest(monkeypatch):
    fake_lookup = AsyncMock(return_value=make_vt_result())
    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        url_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )
    monkeypatch.setattr(url_router, "create_scan", fake_create_scan)

    result = await url_router.analyze_url(
        request=url_router.URLRequest(url="example.com/login"),
        user_ctx=url_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
    )

    analysis = result["result"]

    assert result["guest_mode"] is True
    assert result["url"] == "https://example.com/login"
    assert analysis["indicator_type"] == "url"
    assert analysis["url_info"]["host"] == "example.com"
    assert "risk_score" in analysis
    assert "confidence_score" in analysis
    assert "recommendation" in analysis
    fake_lookup.assert_awaited_once_with(
        "https://example.com/login",
        "url",
    )
    fake_create_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_url_analysis_invalid_url_rejected(monkeypatch):
    fake_lookup = AsyncMock()

    monkeypatch.setattr(
        url_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    with pytest.raises(HTTPException):
        await url_router.analyze_url(
            request=url_router.URLRequest(url="ftp://example.com"),
            user_ctx=url_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
        )

    fake_lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_url_analysis_not_found_returns_unknown_report(monkeypatch):
    fake_lookup = AsyncMock(return_value=make_vt_result("not_found"))
    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        url_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )
    monkeypatch.setattr(url_router, "create_scan", fake_create_scan)

    result = await url_router.analyze_url(
        request=url_router.URLRequest(url="https://missing.example"),
        user_ctx=url_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
    )

    analysis = result["result"]

    assert analysis["status"] == "not_found"
    assert analysis["verdict"] == "unknown"
    assert analysis["confidence"] == "unknown"
    assert analysis["recommendation"]


class FakeURLResponse:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "url": "https://example.com/login",
                    "reputation": -2,
                    "times_submitted": 7,
                    "last_analysis_date": 1715000000,
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 4,
                        "undetected": 5,
                    },
                    "last_analysis_results": {
                        "Engine A": {
                            "category": "malicious",
                            "result": "phishing",
                        },
                        "Engine B": {
                            "category": "harmless",
                            "result": "clean",
                        },
                    },
                    "categories": {
                        "Engine A": "phishing",
                    },
                }
            }
        }


class FakeURLNotFoundResponse:
    status_code = 404


class FakeClient:
    def __init__(self, response, **kwargs):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, headers):
        return self.response


@pytest.mark.asyncio
async def test_virustotal_url_hit_mapping(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(FakeURLResponse(), **kwargs),
    )

    result = await virustotal.check_url("https://example.com/login")

    assert result["status"] == "found"
    assert result["detections"] == 2
    assert result["suspicious_detections"] == 1
    assert result["last_analysis"] == 1715000000
    assert result["community_reputation"] == -2
    assert result["threat_categories"] == [
        {
            "engine": "Engine A",
            "value": "phishing",
        }
    ]
    assert result["flagged_engines"] == [
        {
            "engine": "Engine A",
            "category": "malicious",
            "result": "phishing",
        }
    ]
    assert result["permalink"].startswith(
        "https://www.virustotal.com/gui/url/"
    )


@pytest.mark.asyncio
async def test_virustotal_url_not_found_mapping(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(FakeURLNotFoundResponse(), **kwargs),
    )

    result = await virustotal.check_url("https://missing.example")

    assert result["status"] == "not_found"
    assert result["permalink"].startswith(
        "https://www.virustotal.com/gui/url/"
    )

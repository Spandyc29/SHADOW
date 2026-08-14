import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from routers import ip as ip_router
from services import virustotal
from services.ip.ip_service import get_ip_details
from services.ip.ip_validator import (
    get_ip_classification,
    normalize_ip,
    validate_ip,
)
from services.normalizer import ThreatNormalizer


def run_async(coro):
    return asyncio.run(coro)


def make_vt_ip_result(ip_value="8.8.8.8", status="found", reputation=500):
    if status != "found":
        return {
            "status": status,
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_value}",
        }

    return {
        "status": "found",
        "detections": 0,
        "malicious_detections": 0,
        "suspicious_detections": 0,
        "total_engines": 90,
        "usable_engines": 90,
        "unusable_engines": 0,
        "unusable_breakdown": {},
        "threat_label": None,
        "threat_categories": [],
        "flagged_engines": [],
        "first_seen": None,
        "last_analysis": 1715000000,
        "meaningful_name": ip_value,
        "associated_names": [],
        "file_type": "IP",
        "file_size": None,
        "tags": ["dns-server"],
        "reputation": reputation,
        "community_reputation": reputation,
        "country": "US",
        "asn": 15169,
        "network": "8.8.8.0/24",
        "as_owner": "Google LLC",
        "whois": "Google WHOIS data",
        "jarm": None,
        "last_https_certificate": None,
        "times_submitted": None,
        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_value}",
        "raw": {},
    }


# ==========================================================
# 1. IP VALIDATOR TESTS
# ==========================================================

def test_normalize_ip_valid_ipv4():
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_ip(" 1.1.1.1  ") == "1.1.1.1"
    assert normalize_ip("http://192.168.1.1") == "192.168.1.1"
    assert normalize_ip("10.0.0.1:8080") == "10.0.0.1"


def test_normalize_ip_valid_ipv6():
    assert normalize_ip("::1") == "::1"
    assert normalize_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert normalize_ip("[::1]") == "::1"


def test_normalize_ip_invalid():
    with pytest.raises(ValueError):
        normalize_ip("")

    with pytest.raises(ValueError):
        normalize_ip("999.999.999.999")

    with pytest.raises(ValueError):
        normalize_ip("invalid-ip")


def test_validate_ip():
    assert validate_ip("8.8.8.8") is True
    assert validate_ip("1.1.1.1") is True
    assert validate_ip("127.0.0.1") is True
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("10.0.0.1") is True
    assert validate_ip("2001:4860:4860::8888") is True
    assert validate_ip("999.999.999.999") is False


def test_ip_classification_public_ipv4():
    cls = get_ip_classification("8.8.8.8")
    assert cls["version"] == "IPv4"
    assert cls["is_public"] is True
    assert cls["is_private"] is False
    assert cls["is_loopback"] is False
    assert cls["is_multicast"] is False
    assert cls["is_reserved"] is False


def test_ip_classification_private_ipv4():
    cls_192 = get_ip_classification("192.168.1.1")
    assert cls_192["version"] == "IPv4"
    assert cls_192["is_private"] is True
    assert cls_192["is_public"] is False

    cls_10 = get_ip_classification("10.0.0.1")
    assert cls_10["version"] == "IPv4"
    assert cls_10["is_private"] is True
    assert cls_10["is_public"] is False


def test_ip_classification_loopback_ipv4():
    cls = get_ip_classification("127.0.0.1")
    assert cls["version"] == "IPv4"
    assert cls["is_loopback"] is True
    assert cls["is_public"] is False


def test_ip_classification_ipv6():
    cls_google = get_ip_classification("2001:4860:4860::8888")
    assert cls_google["version"] == "IPv6"
    assert cls_google["is_public"] is True

    cls_loopback = get_ip_classification("::1")
    assert cls_loopback["version"] == "IPv6"
    assert cls_loopback["is_loopback"] is True
    assert cls_loopback["is_public"] is False


# ==========================================================
# 2. IP SERVICE TESTS
# ==========================================================

def test_get_ip_details(monkeypatch):
    monkeypatch.setattr(
        "services.ip.ip_service.get_reverse_dns",
        lambda ip: "dns.google" if ip == "8.8.8.8" else None,
    )

    vt_result = make_vt_ip_result("8.8.8.8")
    details = run_async(get_ip_details("8.8.8.8", vt_result))

    assert details["ip"] == "8.8.8.8"
    assert details["version"] == "IPv4"
    assert details["is_public"] is True
    assert details["is_private"] is False
    assert details["reverse_dns"] == "dns.google"
    assert details["asn"] == 15169
    assert details["as_owner"] == "Google LLC"
    assert details["country"] == "US"


# ==========================================================
# 3. VIRUSTOTAL & NORMALIZER TESTS
# ==========================================================

def test_normalize_ip_result():
    vt_result = make_vt_ip_result("8.8.8.8", reputation=500)
    normalized = ThreatNormalizer.normalize_ip_result("8.8.8.8", vt_result)

    assert normalized["indicator"] == "8.8.8.8"
    assert normalized["indicator_type"] == "ip"
    assert normalized["reputation"] == 500
    assert normalized["reputation_label"] == "Excellent"
    assert normalized["country"] == "US"
    assert normalized["asn"] == 15169
    assert normalized["as_owner"] == "Google LLC"


class FakeIPVTResponse:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "ip": "8.8.8.8",
                    "reputation": 600,
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                    "network": "8.8.8.0/24",
                    "last_analysis_date": 1715000000,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 85,
                        "undetected": 5,
                    },
                    "last_analysis_results": {},
                    "tags": ["dns"],
                    "categories": {},
                }
            }
        }


class FakeClient:
    def __init__(self, response, **kwargs):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, headers):
        return self.response


def test_virustotal_check_ip(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(FakeIPVTResponse(), **kwargs),
    )

    result = run_async(virustotal.check_ip("8.8.8.8"))

    assert result["status"] == "found"
    assert result["detections"] == 0
    assert result["country"] == "US"
    assert result["asn"] == 15169
    assert result["as_owner"] == "Google LLC"
    assert result["permalink"] == "https://www.virustotal.com/gui/ip-address/8.8.8.8"


# ==========================================================
# 4. ROUTER ENDPOINT TESTS
# ==========================================================

def test_ip_analysis_router_guest(monkeypatch):
    fake_lookup = AsyncMock(return_value=make_vt_ip_result("8.8.8.8", reputation=500))
    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        ip_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )
    monkeypatch.setattr(ip_router, "create_scan", fake_create_scan)

    result = run_async(
        ip_router.analyze_ip(
            request=ip_router.IPRequest(ip="8.8.8.8"),
            user_ctx=ip_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
        )
    )

    analysis = result["result"]

    assert result["guest_mode"] is True
    assert result["ip"] == "8.8.8.8"
    assert analysis["indicator_type"] == "ip"
    assert analysis["ip_info"]["version"] == "IPv4"
    assert analysis["ip_info"]["is_public"] is True
    assert "risk_score" in analysis
    assert "confidence_score" in analysis
    assert "recommendation" in analysis

    fake_lookup.assert_awaited_once_with("8.8.8.8", "ip")
    fake_create_scan.assert_not_awaited()


def test_ip_analysis_router_invalid_ip_rejection(monkeypatch):
    fake_lookup = AsyncMock()

    monkeypatch.setattr(
        ip_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    with pytest.raises(HTTPException) as exc_info:
        run_async(
            ip_router.analyze_ip(
                request=ip_router.IPRequest(ip="999.999.999.999"),
                user_ctx=ip_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
            )
        )

    assert exc_info.value.status_code == 400
    fake_lookup.assert_not_awaited()

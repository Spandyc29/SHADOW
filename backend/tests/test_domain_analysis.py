from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from routers import domain as domain_router
from services import virustotal
from services.domain.domain_service import (
    extract_domain_information,
    get_domain_details,
    resolve_dns,
)
from services.domain.domain_validator import normalize_domain, validate_domain
from services.domain.whois_service import (
    _calculate_domain_age,
    _calculate_remaining_time,
    _clean_field,
    _deduplicate_list,
    _format_date,
    _format_dnssec,
)
from services.normalizer import ThreatNormalizer, get_reputation_label


def make_vt_domain_result(status="found", reputation=250):
    if status != "found":
        return {
            "status": status,
            "permalink": "https://www.virustotal.com/gui/domain/example.com",
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
        "first_seen": 1000000000,
        "last_analysis": 1715000000,
        "meaningful_name": "example.com",
        "associated_names": [],
        "file_type": "Domain",
        "file_size": None,
        "tags": [],
        "reputation": reputation,
        "community_reputation": reputation,
        "times_submitted": None,
        "permalink": "https://www.virustotal.com/gui/domain/example.com",
        "raw": {},
    }


def test_deduplicate_list_preserves_order_and_ignores_case():
    raw_status = [
        "clientTransferProhibited",
        "CLIENTTRANSFERPROHIBITED",
        "active",
        "ACTIVE",
        "clientDeleteProhibited",
    ]
    result = _deduplicate_list(raw_status)
    assert result == ["clientTransferProhibited", "active", "clientDeleteProhibited"]


def test_deduplicate_name_servers():
    raw_ns = [
        "NS1.EXAMPLE.COM",
        "ns1.example.com",
        "ns2.example.com",
        "NS2.EXAMPLE.COM",
    ]
    result = _deduplicate_list(raw_ns)
    assert result == ["NS1.EXAMPLE.COM", "ns2.example.com"]


def test_clean_field_empty_fallbacks():
    assert _clean_field(None) == "Not Available"
    assert _clean_field("") == "Not Available"
    assert _clean_field("   ") == "Not Available"
    assert _clean_field([]) == "Not Available"
    assert _clean_field(["   "]) == "Not Available"
    assert _clean_field("Google LLC") == "Google LLC"


def test_format_date():
    dt = datetime(2020, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert _format_date(dt) == "2020-01-15 12:00:00 UTC"
    assert _format_date(None) == "Not Available"
    assert _format_date("") == "Not Available"


def test_calculate_domain_age():
    past_date = datetime.now(timezone.utc) - timedelta(days=730)
    age = _calculate_domain_age(past_date)
    assert "2 year" in age

    assert _calculate_domain_age(None) == "Not Available"


def test_calculate_remaining_time():
    future_date = datetime.now(timezone.utc) + timedelta(days=400)
    remaining = _calculate_remaining_time(future_date)
    assert "1 year" in remaining

    past_date = datetime.now(timezone.utc) - timedelta(days=10)
    assert _calculate_remaining_time(past_date) == "Expired"
    assert _calculate_remaining_time(None) == "Not Available"


def test_reputation_labels():
    assert get_reputation_label(600) == "Excellent"
    assert get_reputation_label(150) == "Good"
    assert get_reputation_label(50) == "Neutral"
    assert get_reputation_label(0) == "Neutral"
    assert get_reputation_label(-10) == "Poor"
    assert get_reputation_label(None) == "Not Available"


def test_format_dnssec():
    assert _format_dnssec("signed") == "Signed"
    assert _format_dnssec(True) == "Signed"
    assert _format_dnssec("unsigned") == "Unsigned"
    assert _format_dnssec(None) == "Unsigned"


def test_normalize_domain_valid_inputs():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("HTTPS://WWW.EXAMPLE.COM/path") == "example.com"
    assert normalize_domain("sub.domain.org") == "sub.domain.org"


def test_normalize_domain_invalid_inputs():
    with pytest.raises(ValueError):
        normalize_domain("")

    with pytest.raises(ValueError):
        normalize_domain("-invalid.com")


def test_validate_domain():
    assert validate_domain("example.com") is True
    assert validate_domain("invalid_domain") is False


def test_extract_domain_information():
    info = extract_domain_information("sub.example.com")
    assert info["domain"] == "sub.example.com"
    assert info["tld"] == "com"
    assert info["second_level_domain"] == "example"
    assert info["subdomain"] == "sub"
    assert info["label_count"] == 3


@pytest.mark.asyncio
async def test_get_domain_details(monkeypatch):
    monkeypatch.setattr(
        "services.domain.domain_service.lookup_whois",
        AsyncMock(
            return_value={
                "registrar": "Test Registrar",
                "creation_date": "2020-01-01 00:00:00 UTC",
                "expiration_date": "2030-01-01 00:00:00 UTC",
                "updated_date": "2024-01-01 00:00:00 UTC",
                "domain_age": "4 years",
                "remaining_time": "5 years",
                "name_servers": ["ns1.example.com"],
                "status": ["active"],
                "dnssec": "Signed",
                "country": "US",
                "org": "Example Org",
                "emails": ["admin@example.com"],
                "available": True,
            }
        ),
    )

    details = await get_domain_details("example.com")

    assert details["domain"] == "example.com"
    assert details["info"]["tld"] == "com"
    assert "dns" in details
    assert details["whois"]["registrar"] == "Test Registrar"
    assert details["whois"]["org"] == "Example Org"
    assert details["whois"]["country"] == "US"
    assert details["whois"]["dnssec"] == "Signed"


@pytest.mark.asyncio
async def test_domain_analysis_router_guest(monkeypatch):
    fake_lookup = AsyncMock(return_value=make_vt_domain_result(reputation=120))
    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        domain_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )
    monkeypatch.setattr(domain_router, "create_scan", fake_create_scan)

    result = await domain_router.analyze_domain(
        request=domain_router.DomainRequest(domain="example.com"),
        user_ctx=domain_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
    )

    analysis = result["result"]

    assert result["guest_mode"] is True
    assert result["domain"] == "example.com"
    assert analysis["indicator_type"] == "domain"
    assert analysis["reputation_label"] == "Good"
    assert "domain_info" in analysis
    assert "dns_info" in analysis
    assert "whois_info" in analysis
    assert "risk_score" in analysis

    fake_lookup.assert_awaited_once_with("example.com", "domain")
    fake_create_scan.assert_not_awaited()


class FakeDomainVTResponse:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "reputation": 5,
                    "last_analysis_date": 1715000000,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10,
                    },
                    "last_analysis_results": {},
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


@pytest.mark.asyncio
async def test_virustotal_check_domain(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(FakeDomainVTResponse(), **kwargs),
    )

    result = await virustotal.check_domain("example.com")

    assert result["status"] == "found"
    assert result["detections"] == 0
    assert result["permalink"] == "https://www.virustotal.com/gui/domain/example.com"

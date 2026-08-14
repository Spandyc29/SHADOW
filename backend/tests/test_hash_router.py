from unittest.mock import AsyncMock

import pytest

from routers import hash as hash_router


# ============================================================
# Test Data
# ============================================================

VALID_SHA256 = "a" * 64


def make_vt_result():
    """
    Minimal valid provider response for the hash endpoint.
    """

    return {
        "status": "found",

        "detections": 0,
        "malicious_detections": 0,
        "suspicious_detections": 0,

        "total_engines": 65,
        "usable_engines": 65,
        "unusable_engines": 0,

        "unusable_breakdown": {
            "type_unsupported": 0,
            "failure": 0,
            "timeout": 0,
            "confirmed_timeout": 0,
        },

        "threat_label": None,
        "threat_categories": [],

        "flagged_engines": [],

        "first_seen": None,
        "last_analysis": None,

        "meaningful_name": None,
        "associated_names": [],

        "file_type": "Win32 EXE",
        "file_size": 1024,

        "tags": [],
        "reputation": 0,

        "times_submitted": 10,

        "permalink": "https://example.invalid/test",
        "raw": {},
    }


# ============================================================
# 1. Authenticated Scan Persists Result
# ============================================================

@pytest.mark.asyncio
async def test_authenticated_hash_analysis_calls_create_scan(monkeypatch):

    fake_lookup = AsyncMock(
        return_value=make_vt_result()
    )

    fake_create_scan = AsyncMock(
        return_value={
            "id": "test-scan-id"
        }
    )

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash=VALID_SHA256
    )

    result = await hash_router.analyze_hash(
        request=request,
        user_ctx=hash_router.UserAuthContext(user_id="00000000-0000-0000-0000-000000000001", access_token="token_a", is_guest=False),
    )

    # Endpoint response
    assert result["guest_mode"] is False
    assert result["analysis_type"] == "hash"
    assert result["hash_type"] == "sha256"
    assert result["scan_id"] == "test-scan-id"

    # Provider lookup happened exactly once
    fake_lookup.assert_awaited_once_with(
        VALID_SHA256,
        "hash",
    )

    # Persistence happened exactly once
    fake_create_scan.assert_awaited_once()

    call_kwargs = fake_create_scan.await_args.kwargs

    assert call_kwargs["user_id"] == (
        "00000000-0000-0000-0000-000000000001"
    )

    assert call_kwargs["analysis_type"] == "hash"

    assert call_kwargs["file_name"] == VALID_SHA256

    assert call_kwargs["md5"] is None
    assert call_kwargs["sha1"] is None
    assert call_kwargs["sha256"] == VALID_SHA256

    assert call_kwargs["vt_status"] == "found"
    assert call_kwargs["vt_detections"] == 0
    assert call_kwargs["vt_total_engines"] == 65


# ============================================================
# 2. Guest Mode Must NOT Persist
# ============================================================

@pytest.mark.asyncio
async def test_guest_hash_analysis_does_not_create_scan(monkeypatch):

    fake_lookup = AsyncMock(
        return_value=make_vt_result()
    )

    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash=VALID_SHA256
    )

    result = await hash_router.analyze_hash(
        request=request,
        user_ctx=hash_router.UserAuthContext(user_id="00000000-0000-0000-0000-000000000001", access_token=None, is_guest=True),
    )

    assert result["guest_mode"] is True
    assert result["analysis_type"] == "hash"
    assert result["hash_type"] == "sha256"

    # Guest responses must not expose DB scan IDs.
    assert "scan_id" not in result

    # Most important assertion:
    fake_create_scan.assert_not_awaited()


# ============================================================
# 3. Correct SHA256 Persistence Mapping
# ============================================================

@pytest.mark.asyncio
async def test_sha256_is_saved_in_correct_column(monkeypatch):

    fake_lookup = AsyncMock(
        return_value=make_vt_result()
    )

    fake_create_scan = AsyncMock(
        return_value={
            "id": "sha256-test-id"
        }
    )

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash=VALID_SHA256
    )

    await hash_router.analyze_hash(
        request=request,
        user_ctx=hash_router.UserAuthContext(user_id="test-user", access_token="token_a", is_guest=False),
    )

    kwargs = fake_create_scan.await_args.kwargs

    assert kwargs["sha256"] == VALID_SHA256
    assert kwargs["sha1"] is None
    assert kwargs["md5"] is None


# ============================================================
# 4. Invalid Hash Must Never Reach Provider or DB
# ============================================================

@pytest.mark.asyncio
async def test_invalid_hash_does_not_lookup_or_persist(monkeypatch):

    fake_lookup = AsyncMock()
    fake_create_scan = AsyncMock()

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash="this-is-not-a-valid-hash"
    )

    with pytest.raises(Exception):
        await hash_router.analyze_hash(
            request=request,
            user_ctx=hash_router.UserAuthContext(user_id="test-user", access_token=None, is_guest=True),
        )

    fake_lookup.assert_not_awaited()
    fake_create_scan.assert_not_awaited()


# ============================================================
# 5. Same Request Does Not Mutate Provider Data
# ============================================================

@pytest.mark.asyncio
async def test_provider_result_not_mutated(monkeypatch):

    provider_data = make_vt_result()

    original = {
        **provider_data,
        "unusable_breakdown": {
            **provider_data["unusable_breakdown"]
        },
        "threat_categories": list(
            provider_data["threat_categories"]
        ),
        "flagged_engines": list(
            provider_data["flagged_engines"]
        ),
        "associated_names": list(
            provider_data["associated_names"]
        ),
        "tags": list(
            provider_data["tags"]
        ),
    }

    fake_lookup = AsyncMock(
        return_value=provider_data
    )

    fake_create_scan = AsyncMock(
        return_value={
            "id": "mutation-test-id"
        }
    )

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash=VALID_SHA256
    )

    await hash_router.analyze_hash(
        request=request,
        user_ctx=hash_router.UserAuthContext(user_id="test-user", access_token="token_a", is_guest=False),
    )

    assert provider_data == original


# ============================================================
# 6. Final Analysis Exists Before Persistence
# ============================================================

@pytest.mark.asyncio
async def test_authenticated_response_contains_analysis(monkeypatch):

    fake_lookup = AsyncMock(
        return_value=make_vt_result()
    )

    fake_create_scan = AsyncMock(
        return_value={
            "id": "analysis-test-id"
        }
    )

    monkeypatch.setattr(
        hash_router.ThreatGateway,
        "lookup_indicator",
        fake_lookup,
    )

    monkeypatch.setattr(
        hash_router,
        "create_scan",
        fake_create_scan,
    )

    request = hash_router.HashRequest(
        hash=VALID_SHA256
    )

    result = await hash_router.analyze_hash(
        request=request,
        user_ctx=hash_router.UserAuthContext(user_id="test-user", access_token="token_a", is_guest=False),
    )

    analysis = result["result"]

    assert "risk_score" in analysis
    assert "verdict" in analysis
    assert "severity" in analysis

    assert "confidence_score" in analysis
    assert "confidence" in analysis

    assert "recommendation" in analysis
    assert "recommended_action" in analysis
    assert "recommendation_priority" in analysis
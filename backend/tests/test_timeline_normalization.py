import pytest

from services.normalizer import ThreatNormalizer
from services import virustotal


VALID_HASH = "a" * 64
VALID_FIRST_SEEN = 1710000000
VALID_LAST_ANALYSIS = 1715000000
VALID_LAST_MODIFIED = 1716000000


def test_normalizer_preserves_valid_timestamps():
    result = ThreatNormalizer.normalize_hash_result(
        VALID_HASH,
        {
            "status": "found",
            "first_seen": VALID_FIRST_SEEN,
            "last_analysis": VALID_LAST_ANALYSIS,
        },
    )

    assert result["first_seen"] == VALID_FIRST_SEEN
    assert result["last_analysis"] == VALID_LAST_ANALYSIS


def test_normalizer_returns_null_for_missing_or_epoch_timestamps():
    for value in (None, "", 0, "0", 1728000, "not-a-date"):
        result = ThreatNormalizer.normalize_hash_result(
            VALID_HASH,
            {
                "status": "not_found",
                "first_seen": value,
                "last_analysis": value,
            },
        )

        assert result["first_seen"] is None
        assert result["last_analysis"] is None


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 2,
                        "undetected": 3,
                    },
                    "last_analysis_results": {},
                    "first_submission_date": VALID_FIRST_SEEN,
                    "last_analysis_date": VALID_LAST_ANALYSIS,
                    "last_modification_date": VALID_LAST_MODIFIED,
                }
            }
        }


class FakeResponseWithoutLastAnalysis:
    status_code = 200

    def json(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {},
                    "last_analysis_results": {},
                    "first_submission_date": None,
                    "last_modification_date": VALID_LAST_MODIFIED,
                }
            }
        }


class FakeResponseWithoutTimestamps:
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
async def test_virustotal_maps_valid_timestamps(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(FakeResponse(), **kwargs),
    )

    result = await virustotal.check_hash(VALID_HASH)

    assert result["first_seen"] == VALID_FIRST_SEEN
    assert result["last_analysis"] == VALID_LAST_ANALYSIS


@pytest.mark.asyncio
async def test_virustotal_uses_last_modification_fallback(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(
            FakeResponseWithoutLastAnalysis(),
            **kwargs,
        ),
    )

    result = await virustotal.check_hash(VALID_HASH)

    assert result["first_seen"] is None
    assert result["last_analysis"] == VALID_LAST_MODIFIED


@pytest.mark.asyncio
async def test_virustotal_not_found_has_no_timestamps(monkeypatch):
    monkeypatch.setattr(
        virustotal.httpx,
        "AsyncClient",
        lambda **kwargs: FakeClient(
            FakeResponseWithoutTimestamps(),
            **kwargs,
        ),
    )

    result = await virustotal.check_hash(VALID_HASH)

    assert result == {"status": "not_found"}

import time
import pytest
from unittest.mock import patch, AsyncMock
import httpx
from fastapi.testclient import TestClient
from main import app
from routers.shadow_ai import apply_guardrail_filter

client = TestClient(app)


def test_guardrail_allows_exact_canonical_risk_max_90():
    # Test that referring to 38/90 when risk_max is 90 does NOT trigger guardrail filter
    raw_reply = "The Risk Engine calculated a Risk Score of 38/90 with MEDIUM risk level."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is False
    assert filtered_reply == raw_reply


def test_guardrail_blocks_fabricated_score_denominator():
    # Test that inventing 38/100 when risk_max is 90 triggers guardrail filter redirect
    raw_reply = "The Risk Engine score is 38/100."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is True
    assert "38/90" in filtered_reply


def test_shadow_ai_chat_accepts_and_preserves_risk_max_90_mocked():
    # Unit test using mocked Groq response to guarantee determinism without rate limits
    scan_context = {
        "indicator_type": "file",
        "target": "suspicious_file.exe",
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
    }

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: {
        "choices": [
            {
                "message": {
                    "content": "The scan's Risk Score is 38/90 (MEDIUM) and Confidence Score is 65/100 (MEDIUM)."
                }
            }
        ]
    }

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        response = client.post("/api/shadow-ai/chat", json={
            "message": "What is the exact risk score and confidence score of this scan?",
            "scanContext": scan_context
        })

    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    reply = data["reply"]
    assert "38/90" in reply
    assert "38/100" not in reply


def test_shadow_ai_chat_accepts_and_preserves_risk_max_90_live():
    scan_context = {
        "indicator_type": "file",
        "target": "suspicious_file.exe",
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
    }

    # Retry up to 3 times in case of remote API rate limiting
    for attempt in range(3):
        response = client.post("/api/shadow-ai/chat", json={
            "message": "What is the exact risk score and confidence score of this scan?",
            "scanContext": scan_context
        })

        assert response.status_code == 200
        data = response.json()
        reply = data.get("reply", "")
        if "trouble responding right now" not in reply:
            normalized_reply = reply.replace('\u202f', ' ').replace('\xa0', ' ')
            assert ("38/90" in normalized_reply or "38 out of 90" in normalized_reply)
            assert "38/100" not in normalized_reply
            assert "38 out of 100" not in normalized_reply
            return
        time.sleep(1.5)

    pytest.skip("Groq API rate limited during test execution")

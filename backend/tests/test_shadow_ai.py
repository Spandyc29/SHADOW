import pytest
from fastapi.testclient import TestClient
from main import app
from routers.shadow_ai import apply_guardrail_filter, ShadowAIChatRequest

client = TestClient(app)


def test_guardrail_filter_verdict_declaring_language():
    # Test verdict pattern detection
    raw_reply = "My final verdict is MALICIOUS and you should quarantine this file."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is True
    assert "I can't provide an independent verdict" in filtered_reply
    assert "SUSPICIOUS" in filtered_reply


def test_guardrail_filter_fabricated_score():
    # Test numeric score fabrication detection
    raw_reply = "Based on my calculation, the risk score is 62/100."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is True
    assert "I can't calculate an independent score" in filtered_reply
    assert "38/90" in filtered_reply


def test_guardrail_filter_legitimate_score_reference():
    # Test that referring to the actual authoritative score does NOT trigger guardrail
    raw_reply = "The risk score of 38/90 reflects medium risk based on 2 suspicious detections."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
        "confidence_score": 65,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is False
    assert filtered_reply == raw_reply


def test_guardrail_filter_legitimate_explanation():
    # Test that normal explanations pass without filtering
    raw_reply = "The Risk Engine marked this indicator as SUSPICIOUS because of high network activity and low community trust."
    scan_context = {
        "verdict": "SUSPICIOUS",
        "risk_score": 38,
        "risk_max": 90,
    }
    filtered_reply, was_filtered = apply_guardrail_filter(raw_reply, scan_context)

    assert was_filtered is False
    assert filtered_reply == raw_reply


def test_shadow_ai_chat_empty_message():
    response = client.post("/api/shadow-ai/chat", json={"message": "   "})
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"]


@pytest.mark.parametrize("indicator_type,target", [
    ("file", "malware.exe"),
    ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("ip", "192.168.1.1"),
    ("domain", "suspicious-domain.com"),
    ("url", "https://malicious-site.com/login"),
])
def test_shadow_ai_indicator_types_context_acceptance(indicator_type, target):
    # Verify backend chat endpoint accepts scan context for all 5 indicator types
    scan_ctx = {
        "indicator_type": indicator_type,
        "target": target,
        "verdict": "SUSPICIOUS",
        "risk_score": 45,
        "risk_max": 100,
        "confidence_score": 80,
        "confidence_max": 100,
        "threat_label": "Phishing",
        "detections": "3/60 security engines",
        "risk_factors": "Suspicious TLD, Recent registration",
        "tags": "verified, phishing",
        "scan_id": f"SCAN-{indicator_type.upper()}-123",
        "technical_details": "DNS IP: 1.2.3.4",
    }

    # Post chat request with scan context
    response = client.post("/api/shadow-ai/chat", json={
        "message": "Explain this scan",
        "scanContext": scan_ctx
    })

    assert response.status_code == 200
    res_json = response.json()
    assert "reply" in res_json
    assert "filtered" in res_json

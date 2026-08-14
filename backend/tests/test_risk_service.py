import pytest

from services.risk_service import RiskService


def make_result(
    *,
    status="found",
    detections=0,
    threat_label=None,
    threat_categories=None,
    tags=None,
    reputation=0,
):
    """
    Creates a minimal normalized threat-intelligence result
    for testing RiskService.
    """

    return {
        "status": status,
        "detections": detections,
        "threat_label": threat_label,
        "threat_categories": threat_categories or [],
        "tags": tags or [],
        "reputation": reputation,
    }


# ---------------------------------------------------------
# 1. UNKNOWN / NOT FOUND SAFETY
# ---------------------------------------------------------

def test_not_found_is_never_clean():
    data = make_result(status="not_found")

    result = RiskService.calculate(data)

    assert result["verdict"] != "clean"


# ---------------------------------------------------------
# 2. CLEAN BASELINE
# ---------------------------------------------------------

def test_zero_detection_clean_baseline():
    data = make_result(
        detections=0,
        threat_label=None,
        threat_categories=[],
        tags=[],
        reputation=0,
    )

    result = RiskService.calculate(data)

    assert result["verdict"] == "clean"
    assert result["gate_applied"] is False


# ---------------------------------------------------------
# 3. SINGLE DETECTION SHOULD NOT BE MALICIOUS
# ---------------------------------------------------------

def test_single_detection_not_malicious():
    data = make_result(detections=1)

    result = RiskService.calculate(data)

    assert result["verdict"] != "malicious"


# ---------------------------------------------------------
# 4. LOW DETECTION COUNT SHOULD NOT BY ITSELF
#    PRODUCE MALICIOUS VERDICT
# ---------------------------------------------------------

def test_three_detections_not_malicious_by_themselves():
    data = make_result(detections=3)

    result = RiskService.calculate(data)

    assert result["verdict"] != "malicious"


# ---------------------------------------------------------
# 5. QUALITY GATE
#
# Strong supporting evidence + fewer than 5 detections
# must never produce final MALICIOUS verdict.
# ---------------------------------------------------------

def test_quality_gate_caps_low_detection_case():
    data = make_result(
        detections=4,
        threat_label="trojan.generic",
        threat_categories=[
            {"value": "trojan", "count": 10}
        ],
        tags=[
            "obfuscated",
            "packed",
            "runtime-modules",
        ],
        reputation=-10,
    )

    result = RiskService.calculate(data)

    assert result["verdict"] != "malicious"

    # If the raw score actually crossed the malicious threshold,
    # the quality gate must explain the cap.
    if result["risk_score"] >= 50:
        assert result["gate_applied"] is True
        assert result["gate_reason"] is not None


# ---------------------------------------------------------
# 6. DETECTION GATE BOUNDARY
#
# Exactly 5 detections should no longer be blocked merely
# because of the minimum-detection quality gate.
# ---------------------------------------------------------

def test_five_detections_not_blocked_by_detection_gate():
    data = make_result(
        detections=5,
        threat_label="trojan.generic",
        threat_categories=[
            {"value": "trojan", "count": 10}
        ],
        tags=[
            "obfuscated",
            "packed",
        ],
        reputation=-10,
    )

    result = RiskService.calculate(data)

    assert result["gate_applied"] is False


# ---------------------------------------------------------
# 7. NEGATIVE REPUTATION MUST NOT PRODUCE CLEAN
# ---------------------------------------------------------

def test_negative_reputation_not_clean():
    data = make_result(
        detections=0,
        reputation=-10,
    )

    result = RiskService.calculate(data)

    assert result["verdict"] != "clean"


# ---------------------------------------------------------
# 8. MALICIOUS CLASSIFICATION MUST NOT PRODUCE CLEAN
# ---------------------------------------------------------

def test_malicious_classification_not_clean():
    data = make_result(
        detections=0,
        threat_label="trojan.generic",
        threat_categories=[
            {"value": "trojan", "count": 5}
        ],
    )

    result = RiskService.calculate(data)

    assert result["verdict"] != "clean"


# ---------------------------------------------------------
# 9. OUTPUT STRUCTURE
# ---------------------------------------------------------

def test_risk_output_structure():
    data = make_result(detections=3)

    result = RiskService.calculate(data)

    required_fields = {
        "risk_score",
        "verdict",
        "severity",
        "risk_factors",
        "gate_applied",
        "gate_reason",
    }

    assert required_fields.issubset(result.keys())

    assert isinstance(result["risk_factors"], list)
    assert isinstance(result["gate_applied"], bool)


# ---------------------------------------------------------
# 10. DETERMINISM
# ---------------------------------------------------------

def test_same_input_produces_same_result():
    data = make_result(
        detections=3,
        threat_label="trojan.corrupted",
        threat_categories=[
            {"value": "trojan", "count": 2}
        ],
        tags=["obfuscated"],
        reputation=0,
    )

    first = RiskService.calculate(data)
    second = RiskService.calculate(data)

    assert first == second
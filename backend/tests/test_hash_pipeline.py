from services.normalizer import ThreatNormalizer
from services.risk_service import RiskService
from services.confidence_service import ConfidenceService
from services.recommendation_service import RecommendationService


# ============================================================
# Helpers
# ============================================================

TEST_HASH = "a" * 64


def make_vt_result(
    *,
    status="found",
    malicious=0,
    suspicious=0,
    harmless=0,
    undetected=65,
    total_engines=65,
    usable_engines=65,
    threat_label=None,
    threat_categories=None,
    tags=None,
    reputation=0,
    times_submitted=1,
):
    """
    Create provider-style VirusTotal data for SHADOW pipeline tests.
    """

    threat_categories = threat_categories or []
    tags = tags or []

    detections = malicious

    unusable_engines = max(total_engines - usable_engines, 0)

    return {
        "status": status,

        "detections": detections,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,

        "total_engines": total_engines,
        "usable_engines": usable_engines,
        "unusable_engines": unusable_engines,

        "unusable_breakdown": {
            "type_unsupported": unusable_engines,
            "failure": 0,
            "timeout": 0,
            "confirmed_timeout": 0,
        },

        "threat_label": threat_label,
        "threat_categories": threat_categories,

        "flagged_engines": [],

        "first_seen": None,
        "last_analysis": None,

        "meaningful_name": None,
        "associated_names": [],

        "file_type": "Win32 EXE",
        "file_size": 1024,

        "tags": tags,
        "reputation": reputation,

        "times_submitted": times_submitted,

        "permalink": "https://example.invalid/test",
        "raw": {},
    }


def run_pipeline(vt_result):
    """
    Simulates the SHADOW hash-analysis pipeline:

    Provider
        ↓
    Normalizer
        ↓
    Risk Engine
        ↓
    Confidence Engine
        ↓
    Recommendation Engine
    """

    normalized = ThreatNormalizer.normalize_hash_result(
        TEST_HASH,
        vt_result
    )

    risk_result = RiskService.calculate(normalized)

    normalized["risk_score"] = risk_result["risk_score"]
    normalized["verdict"] = risk_result["verdict"]
    normalized["severity"] = risk_result["severity"]
    normalized["risk_factors"] = risk_result["risk_factors"]
    normalized["gate_applied"] = risk_result["gate_applied"]
    normalized["gate_reason"] = risk_result["gate_reason"]

    confidence_result = ConfidenceService.calculate(normalized)

    normalized["confidence_score"] = confidence_result[
        "confidence_score"
    ]
    normalized["confidence"] = confidence_result["confidence"]
    normalized["confidence_factors"] = confidence_result[
        "confidence_factors"
    ]
    normalized["confidence_metrics"] = confidence_result[
        "confidence_metrics"
    ]

    recommendation_result = RecommendationService.generate(
        normalized
    )

    normalized["recommendation"] = recommendation_result[
        "recommendation"
    ]
    normalized["recommended_action"] = recommendation_result[
        "action"
    ]
    normalized["recommendation_priority"] = recommendation_result[
        "priority"
    ]

    return normalized


# ============================================================
# 1. Clean Pipeline
# ============================================================

def test_clean_hash_pipeline():

    vt_result = make_vt_result(
        malicious=0,
        suspicious=0,
        harmless=5,
        undetected=60,
        threat_label=None,
        threat_categories=[],
        tags=[],
        reputation=0,
        times_submitted=10,
    )

    result = run_pipeline(vt_result)

    assert result["status"] == "found"
    assert result["detections"] == 0

    assert result["verdict"] == "clean"
    assert result["risk_score"] < 20

    assert result["gate_applied"] is False

    assert result["confidence"] in {
        "low",
        "medium",
        "high",
    }

    assert result["recommendation"] is not None
    assert result["recommended_action"] is not None
    assert result["recommendation_priority"] is not None


# ============================================================
# 2. Suspicious Pipeline
# ============================================================

def test_suspicious_hash_pipeline():

    vt_result = make_vt_result(
        malicious=3,
        suspicious=0,
        harmless=5,
        undetected=57,
        threat_label="trojan.corrupted",
        threat_categories=["trojan"],
        tags=["obfuscated"],
        reputation=0,
        times_submitted=2,
    )

    result = run_pipeline(vt_result)

    assert result["status"] == "found"

    assert result["detections"] == 3

    assert result["verdict"] == "suspicious"

    assert result["risk_score"] >= 20

    assert result["confidence"] in {
        "low",
        "medium",
        "high",
    }

    assert result["recommendation"] is not None
    assert result["recommended_action"] is not None


# ============================================================
# 3. Detection Quality Gate
# ============================================================

def test_quality_gate_pipeline():

    vt_result = make_vt_result(
        malicious=3,
        suspicious=0,
        harmless=0,
        undetected=62,
        threat_label="trojan",
        threat_categories=["trojan"],
        tags=[
            "obfuscated",
            "packed",
        ],
        reputation=-10,
        times_submitted=20,
    )

    result = run_pipeline(vt_result)

    # Even if supporting evidence pushes risk upward,
    # fewer than 5 detections must never produce MALICIOUS.

    assert result["detections"] < 5

    assert result["verdict"] != "malicious"

    assert result["verdict"] == "suspicious"

    # If raw score crosses the malicious threshold,
    # the quality gate must be visible.
    if result["risk_score"] >= 50:
        assert result["gate_applied"] is True
        assert result["gate_reason"] is not None


# ============================================================
# 4. Malicious Pipeline
# ============================================================

def test_malicious_hash_pipeline():

    vt_result = make_vt_result(
        malicious=15,
        suspicious=2,
        harmless=3,
        undetected=45,
        threat_label="trojan",
        threat_categories=["trojan"],
        tags=[
            "obfuscated",
            "packed",
        ],
        reputation=-20,
        times_submitted=50,
    )

    result = run_pipeline(vt_result)

    assert result["status"] == "found"

    assert result["detections"] >= 5

    assert result["risk_score"] >= 50

    assert result["verdict"] == "malicious"

    assert result["gate_applied"] is False

    assert result["recommendation"] is not None
    assert result["recommended_action"] is not None


# ============================================================
# 5. Not Found Must Never Become Clean
# ============================================================

def test_not_found_pipeline():

    vt_result = {
        "status": "not_found"
    }

    result = run_pipeline(vt_result)

    assert result["status"] == "not_found"

    assert result["verdict"] != "clean"

    assert result["confidence"] == "unknown"

    assert result["recommendation"] is not None

    recommendation_text = result["recommendation"].lower()

    # No false reassurance.
    assert "safe" not in recommendation_text
    assert "confirmed clean" not in recommendation_text


# ============================================================
# 6. Zero Usable Engines Must Not Crash
# ============================================================

def test_zero_usable_engines_pipeline():

    vt_result = make_vt_result(
        malicious=0,
        suspicious=0,
        harmless=0,
        undetected=0,
        total_engines=20,
        usable_engines=0,
        threat_label=None,
        threat_categories=[],
        tags=[],
        reputation=0,
    )

    result = run_pipeline(vt_result)

    assert result is not None

    assert result["confidence"] != "high"

    assert result["confidence_score"] >= 0

    assert result["confidence_metrics"][
        "usable_engines"
    ] == 0


# ============================================================
# 7. Partial Provider Data
# ============================================================

def test_partial_provider_data_does_not_crash():

    vt_result = {
        "status": "found",
        "detections": 0,
        "total_engines": 0,
        "usable_engines": 0,
    }

    result = run_pipeline(vt_result)

    assert result is not None

    assert "risk_score" in result
    assert "verdict" in result

    assert "confidence_score" in result
    assert "confidence" in result

    assert "recommendation" in result


# ============================================================
# 8. Final Output Contract
# ============================================================

def test_final_pipeline_output_contract():

    vt_result = make_vt_result(
        malicious=3,
        suspicious=0,
        harmless=5,
        undetected=57,
        threat_label="trojan.corrupted",
        threat_categories=["trojan"],
        tags=["obfuscated"],
        reputation=0,
        times_submitted=2,
    )

    result = run_pipeline(vt_result)

    required_fields = {
        "indicator",
        "indicator_type",
        "status",

        "detections",
        "total_engines",
        "usable_engines",

        "risk_score",
        "verdict",
        "severity",
        "risk_factors",

        "gate_applied",
        "gate_reason",

        "confidence_score",
        "confidence",
        "confidence_factors",
        "confidence_metrics",

        "recommendation",
        "recommended_action",
        "recommendation_priority",
    }

    for field in required_fields:
        assert field in result


# ============================================================
# 9. Pipeline Determinism
# ============================================================

def test_same_input_produces_same_pipeline_result():

    vt_result = make_vt_result(
        malicious=3,
        suspicious=0,
        harmless=5,
        undetected=57,
        threat_label="trojan.corrupted",
        threat_categories=["trojan"],
        tags=["obfuscated"],
        reputation=0,
        times_submitted=2,
    )

    first = run_pipeline(vt_result)

    second = run_pipeline(vt_result)

    assert first == second
from services.confidence_service import ConfidenceService


def make_result(
    *,
    status="found",
    usable_engines=65,
    total_engines=74,
    malicious_detections=0,
    suspicious_detections=0,
    threat_label=None,
    threat_categories=None,
    tags=None,
    reputation=None,
    times_submitted=0,
):
    """
    Creates minimal normalized threat-intelligence data
    for testing ConfidenceService.
    """

    return {
        "status": status,
        "usable_engines": usable_engines,
        "total_engines": total_engines,

        "malicious_detections": malicious_detections,
        "suspicious_detections": suspicious_detections,

        "threat_label": threat_label,
        "threat_categories": threat_categories or [],
        "tags": tags or [],
        "reputation": reputation,
        "times_submitted": times_submitted,
    }


# ---------------------------------------------------------
# 1. NOT FOUND -> UNKNOWN CONFIDENCE
# ---------------------------------------------------------

def test_not_found_returns_unknown_confidence():
    data = make_result(status="not_found")

    result = ConfidenceService.calculate(data)

    assert result["confidence"] == "unknown"


# ---------------------------------------------------------
# 2. ZERO USABLE ENGINES
#
# Most important edge case:
# must NOT cause division-by-zero.
# ---------------------------------------------------------

def test_zero_usable_engines_does_not_crash():
    data = make_result(
        usable_engines=0,
        total_engines=74,
        malicious_detections=0,
        suspicious_detections=0,
    )

    result = ConfidenceService.calculate(data)

    assert isinstance(result, dict)
    assert "confidence_score" in result
    assert "confidence" in result


# ---------------------------------------------------------
# 3. ZERO USABLE ENGINES MUST NOT PRODUCE HIGH CONFIDENCE
# ---------------------------------------------------------

def test_zero_usable_engines_not_high_confidence():
    data = make_result(
        usable_engines=0,
        total_engines=74,
    )

    result = ConfidenceService.calculate(data)

    assert result["confidence"] != "high"


# ---------------------------------------------------------
# 4. VERY SPARSE ENGINE COVERAGE
# ---------------------------------------------------------

def test_sparse_engine_coverage_not_high_confidence():
    data = make_result(
        usable_engines=3,
        total_engines=74,
        malicious_detections=1,
    )

    result = ConfidenceService.calculate(data)

    assert result["confidence"] != "high"


# ---------------------------------------------------------
# 5. STRONG ENGINE COVERAGE
# ---------------------------------------------------------

def test_high_engine_coverage_contributes_confidence():
    data = make_result(
        usable_engines=65,
        total_engines=74,
    )

    result = ConfidenceService.calculate(data)

    assert result["confidence_score"] > 0


# ---------------------------------------------------------
# 6. LOW DETECTION PERCENTAGE
#
# 3 / 65 ~= 4.62%
# This is the same kind of case tested manually earlier.
# ---------------------------------------------------------

def test_low_detection_percentage():
    data = make_result(
        usable_engines=65,
        total_engines=74,
        malicious_detections=3,
        suspicious_detections=0,
        threat_label="trojan.corrupted",
        threat_categories=[
            {"value": "trojan", "count": 2}
        ],
        tags=["obfuscated"],
        reputation=0,
        times_submitted=2,
    )

    result = ConfidenceService.calculate(data)

    metrics = result["confidence_metrics"]

    assert metrics["usable_engines"] == 65
    assert metrics["flagged_engines"] == 3

    assert abs(
        metrics["detection_percentage"] - 4.62
    ) < 0.1


# ---------------------------------------------------------
# 7. SUSPICIOUS DETECTIONS MUST COUNT AS FLAGGED
# ---------------------------------------------------------

def test_suspicious_detections_count_as_flagged():
    data = make_result(
        usable_engines=50,
        total_engines=60,
        malicious_detections=2,
        suspicious_detections=3,
    )

    result = ConfidenceService.calculate(data)

    assert (
        result["confidence_metrics"]["flagged_engines"]
        == 5
    )


# ---------------------------------------------------------
# 8. EVIDENCE COMPLETENESS
# ---------------------------------------------------------

def test_metadata_increases_confidence():
    minimal = make_result(
        usable_engines=50,
        total_engines=60,
    )

    complete = make_result(
        usable_engines=50,
        total_engines=60,
        threat_label="trojan.generic",
        threat_categories=[
            {"value": "trojan", "count": 5}
        ],
        tags=["obfuscated"],
        reputation=0,
    )

    minimal_result = ConfidenceService.calculate(minimal)
    complete_result = ConfidenceService.calculate(complete)

    assert (
        complete_result["confidence_score"]
        >= minimal_result["confidence_score"]
    )


# ---------------------------------------------------------
# 9. TIMES SUBMITTED CONTRIBUTES CONFIDENCE
# ---------------------------------------------------------

def test_submission_history_increases_confidence():
    rare = make_result(
        times_submitted=1
    )

    established = make_result(
        times_submitted=20
    )

    rare_result = ConfidenceService.calculate(rare)
    established_result = ConfidenceService.calculate(established)

    assert (
        established_result["confidence_score"]
        >= rare_result["confidence_score"]
    )


# ---------------------------------------------------------
# 10. OUTPUT STRUCTURE
# ---------------------------------------------------------

def test_confidence_output_structure():
    data = make_result()

    result = ConfidenceService.calculate(data)

    required_fields = {
        "confidence_score",
        "confidence",
        "confidence_factors",
        "confidence_metrics",
    }

    assert required_fields.issubset(result.keys())

    assert isinstance(result["confidence_score"], int)
    assert isinstance(result["confidence_factors"], list)
    assert isinstance(result["confidence_metrics"], dict)


# ---------------------------------------------------------
# 11. SCORE MUST REMAIN WITHIN 0-100
# ---------------------------------------------------------

def test_confidence_score_range():
    data = make_result(
        usable_engines=100,
        total_engines=100,
        malicious_detections=100,
        threat_label="trojan.generic",
        threat_categories=[
            {"value": "trojan", "count": 100}
        ],
        tags=["obfuscated"],
        reputation=-100,
        times_submitted=10000,
    )

    result = ConfidenceService.calculate(data)

    assert 0 <= result["confidence_score"] <= 100


# ---------------------------------------------------------
# 12. DETERMINISM
# ---------------------------------------------------------

def test_same_input_produces_same_confidence():
    data = make_result(
        usable_engines=65,
        total_engines=74,
        malicious_detections=3,
        suspicious_detections=0,
        threat_label="trojan.corrupted",
        threat_categories=[
            {"value": "trojan", "count": 2}
        ],
        tags=["obfuscated"],
        reputation=0,
        times_submitted=2,
    )

    first = ConfidenceService.calculate(data)
    second = ConfidenceService.calculate(data)

    assert first == second
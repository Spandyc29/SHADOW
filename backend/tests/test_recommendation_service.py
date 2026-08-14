from services.recommendation_service import RecommendationService


def make_result(
    *,
    status="found",
    verdict="suspicious",
    severity="medium",
    confidence="medium",
    risk_score=38,
):
    """
    Creates minimal analyzed threat data required
    by RecommendationService.
    """

    return {
        "status": status,
        "verdict": verdict,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
    }


# ---------------------------------------------------------
# 1. OUTPUT STRUCTURE
# ---------------------------------------------------------

def test_recommendation_output_structure():
    data = make_result()

    result = RecommendationService.generate(data)

    required_fields = {
        "recommendation",
        "action",
        "priority",
    }

    assert required_fields.issubset(result.keys())

    assert isinstance(result["recommendation"], str)
    assert isinstance(result["action"], str)
    assert isinstance(result["priority"], str)


# ---------------------------------------------------------
# 2. CLEAN + HIGH CONFIDENCE
# ---------------------------------------------------------

def test_clean_high_confidence():
    data = make_result(
        verdict="clean",
        severity="low",
        confidence="high",
        risk_score=0,
    )

    result = RecommendationService.generate(data)

    assert result["recommendation"]
    assert result["action"]
    assert result["priority"]


# ---------------------------------------------------------
# 3. SUSPICIOUS + MEDIUM CONFIDENCE
# Current real-world style SHADOW case.
# ---------------------------------------------------------

def test_suspicious_medium_confidence():
    data = make_result(
        verdict="suspicious",
        severity="medium",
        confidence="medium",
        risk_score=38,
    )

    result = RecommendationService.generate(data)

    assert result["recommendation"]
    assert result["action"]
    assert result["priority"]


# ---------------------------------------------------------
# 4. MALICIOUS + HIGH CONFIDENCE
# ---------------------------------------------------------

def test_malicious_high_confidence():
    data = make_result(
        verdict="malicious",
        severity="high",
        confidence="high",
        risk_score=70,
    )

    result = RecommendationService.generate(data)

    assert result["recommendation"]
    assert result["action"]
    assert result["priority"]


# ---------------------------------------------------------
# 5. CRITICAL MALICIOUS CASE
# ---------------------------------------------------------

def test_critical_malicious_case():
    data = make_result(
        verdict="malicious",
        severity="critical",
        confidence="high",
        risk_score=85,
    )

    result = RecommendationService.generate(data)

    assert result["recommendation"]
    assert result["action"]
    assert result["priority"]


# ---------------------------------------------------------
# 6. NOT FOUND MUST NOT BE REASSURING
# ---------------------------------------------------------

def test_not_found_does_not_claim_clean():
    data = make_result(
        status="not_found",
        verdict="unknown",
        severity="unknown",
        confidence="unknown",
        risk_score=0,
    )

    result = RecommendationService.generate(data)

    text = (
        result["recommendation"]
        + " "
        + result["action"]
    ).lower()

    # Unknown intelligence must never be represented
    # as a confirmed clean/safe result.
    forbidden_phrases = [
        "confirmed clean",
        "confirmed safe",
        "definitely safe",
        "no threat exists",
    ]

    for phrase in forbidden_phrases:
        assert phrase not in text


# ---------------------------------------------------------
# 7. LOW CONFIDENCE MALICIOUS RESULT
#
# Recommendation should still exist even when the
# underlying evidence confidence is weak.
# ---------------------------------------------------------

def test_malicious_low_confidence_still_returns_recommendation():
    data = make_result(
        verdict="malicious",
        severity="high",
        confidence="low",
        risk_score=60,
    )

    result = RecommendationService.generate(data)

    assert result["recommendation"]
    assert result["action"]
    assert result["priority"]


# ---------------------------------------------------------
# 8. UNKNOWN CONFIDENCE
# ---------------------------------------------------------

def test_unknown_confidence_does_not_crash():
    data = make_result(
        verdict="suspicious",
        severity="medium",
        confidence="unknown",
        risk_score=30,
    )

    result = RecommendationService.generate(data)

    assert isinstance(result, dict)
    assert result["recommendation"]


# ---------------------------------------------------------
# 9. RECOMMENDATION MUST NOT MODIFY INPUT
# ---------------------------------------------------------

def test_recommendation_does_not_modify_analysis():
    data = make_result(
        verdict="suspicious",
        severity="medium",
        confidence="medium",
        risk_score=38,
    )

    original = data.copy()

    RecommendationService.generate(data)

    assert data == original


# ---------------------------------------------------------
# 10. RISK SCORE / VERDICT MUST REMAIN AUTHORITATIVE
#
# Recommendation Engine is an interpretation layer.
# It must not return replacement risk calculations.
# ---------------------------------------------------------

def test_recommendation_does_not_rescore_risk():
    data = make_result()

    result = RecommendationService.generate(data)

    assert "risk_score" not in result
    assert "verdict" not in result
    assert "severity" not in result
    assert "confidence_score" not in result


# ---------------------------------------------------------
# 11. DETERMINISM
# ---------------------------------------------------------

def test_same_input_produces_same_recommendation():
    data = make_result(
        verdict="suspicious",
        severity="medium",
        confidence="medium",
        risk_score=38,
    )

    first = RecommendationService.generate(data)
    second = RecommendationService.generate(data)

    assert first == second
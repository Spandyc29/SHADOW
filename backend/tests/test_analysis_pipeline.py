from services.analysis_pipeline import AnalysisPipeline


def make_evidence(
    *,
    status="found",
    detections=0,
    malicious_detections=0,
    suspicious_detections=0,
    total_engines=65,
    usable_engines=65,
    threat_label=None,
    threat_categories=None,
    tags=None,
    reputation=0,
):
    return {
        "indicator": "a" * 64,
        "indicator_type": "hash",

        "status": status,

        "detections": detections,
        "malicious_detections": malicious_detections,
        "suspicious_detections": suspicious_detections,

        "total_engines": total_engines,
        "usable_engines": usable_engines,

        "threat_label": threat_label,
        "threat_categories": threat_categories or [],
        "tags": tags or [],
        "reputation": reputation,
    }


# ---------------------------------------------------------
# 1. Final Output Contract
# ---------------------------------------------------------

def test_pipeline_output_contract():

    result = AnalysisPipeline.run(
        make_evidence()
    )

    required_fields = {
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

        "report",
    }

    assert required_fields.issubset(result.keys())


# ---------------------------------------------------------
# 2. Original Evidence Must Be Preserved
# ---------------------------------------------------------

def test_pipeline_preserves_canonical_evidence():

    data = make_evidence(
        detections=3,
        malicious_detections=3,
        threat_label="trojan.generic",
        tags=["obfuscated"],
    )

    result = AnalysisPipeline.run(data)

    assert result["indicator"] == data["indicator"]
    assert result["indicator_type"] == "hash"
    assert result["status"] == data["status"]
    assert result["detections"] == 3
    assert result["threat_label"] == "trojan.generic"


# ---------------------------------------------------------
# 3. Pipeline Must Not Mutate Caller Input
# ---------------------------------------------------------

def test_pipeline_does_not_mutate_input():

    data = make_evidence(
        detections=3,
        malicious_detections=3,
        threat_label="trojan.generic",
        threat_categories=["trojan"],
        tags=["obfuscated"],
    )

    original = {
        **data,
        "threat_categories": list(
            data["threat_categories"]
        ),
        "tags": list(data["tags"]),
    }

    AnalysisPipeline.run(data)

    assert data == original

    assert "risk_score" not in data
    assert "confidence_score" not in data
    assert "recommendation" not in data


# ---------------------------------------------------------
# 4. Clean Analysis
# ---------------------------------------------------------

def test_clean_analysis():

    result = AnalysisPipeline.run(
        make_evidence(
            detections=0,
            malicious_detections=0,
            suspicious_detections=0,
            reputation=0,
        )
    )

    assert result["verdict"] == "clean"
    assert result["gate_applied"] is False

    assert result["confidence"] in {
        "low",
        "medium",
        "high",
    }

    assert result["recommendation"]


# ---------------------------------------------------------
# 5. Quality Gate
# ---------------------------------------------------------

def test_quality_gate_is_preserved():

    result = AnalysisPipeline.run(
        make_evidence(
            detections=4,
            malicious_detections=4,
            threat_label="trojan.generic",
            threat_categories=["trojan"],
            tags=[
                "obfuscated",
                "packed",
            ],
            reputation=-10,
        )
    )

    assert result["verdict"] != "malicious"

    if result["risk_score"] >= 50:
        assert result["gate_applied"] is True
        assert result["gate_reason"] is not None


# ---------------------------------------------------------
# 6. Normal Malicious Case Has No Gate
# ---------------------------------------------------------

def test_malicious_analysis_not_gate_capped():

    result = AnalysisPipeline.run(
        make_evidence(
            detections=15,
            malicious_detections=15,
            suspicious_detections=2,
            threat_label="trojan.generic",
            threat_categories=["trojan"],
            tags=[
                "obfuscated",
                "packed",
            ],
            reputation=-20,
        )
    )

    assert result["verdict"] == "malicious"

    assert result["gate_applied"] is False
    assert result["gate_reason"] is None


# ---------------------------------------------------------
# 7. Unknown Safety
# ---------------------------------------------------------

def test_not_found_remains_unknown():

    result = AnalysisPipeline.run(
        make_evidence(
            status="not_found",
            total_engines=0,
            usable_engines=0,
        )
    )

    assert result["verdict"] != "clean"
    assert result["confidence"] == "unknown"

    assert result["recommendation"]


# ---------------------------------------------------------
# 8. Zero Usable Engines
# ---------------------------------------------------------

def test_zero_usable_engines_does_not_crash():

    result = AnalysisPipeline.run(
        make_evidence(
            total_engines=20,
            usable_engines=0,
        )
    )

    assert result["confidence"] != "high"
    assert result["confidence_score"] >= 0


# ---------------------------------------------------------
# 9. Determinism
# ---------------------------------------------------------

def test_pipeline_is_deterministic():

    data = make_evidence(
        detections=3,
        malicious_detections=3,
        threat_label="trojan.generic",
        threat_categories=["trojan"],
        tags=["obfuscated"],
        reputation=0,
    )

    first = AnalysisPipeline.run(data)
    second = AnalysisPipeline.run(data)

    assert first == second


# ---------------------------------------------------------
# 10. Analysis Layers Remain Separate
# ---------------------------------------------------------

def test_pipeline_keeps_analysis_layers_separate():

    result = AnalysisPipeline.run(
        make_evidence(
            detections=3,
            malicious_detections=3,
        )
    )

    # Risk output
    assert "risk_score" in result
    assert "verdict" in result

    # Confidence output
    assert "confidence_score" in result
    assert "confidence" in result

    # Recommendation output
    assert "recommendation" in result
    assert "recommended_action" in result

    # All three outputs coexist rather than replacing
    # one another.
    assert result["risk_score"] is not None
    assert result["confidence_score"] is not None
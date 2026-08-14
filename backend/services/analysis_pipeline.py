from typing import Dict, Any

from services.risk_service import RiskService
from services.confidence_service import ConfidenceService
from services.recommendation_service import RecommendationService
from services.report_engine import ReportEngine


class AnalysisPipeline:
    """
    SHADOW V1 Analysis Pipeline.

    Orchestrates SHADOW's deterministic analysis layers:

        Canonical Evidence
              ↓
        Risk Engine
              ↓
        Confidence Engine
              ↓
        Recommendation Engine
              ↓
        SHADOW Report Engine
              ↓
        Final Analysis

    Responsibilities:
    - Coordinate analysis services.
    - Preserve separation between risk, confidence,
      and recommendation logic.
    - Return one enriched SHADOW analysis object.

    Does NOT:
    - Query threat-intelligence providers.
    - Normalize provider responses.
    - Persist scans.
    - Aggregate child IOC risk into parent risk.
    - Use AI/LLMs.
    """

    @staticmethod
    def run(normalized: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run SHADOW analysis on canonical normalized evidence.

        The input dictionary is copied before enrichment so the
        caller's original normalized object is not modified.
        """

        analysis = normalized.copy()

        # --------------------------------------------------
        # 1. Risk Analysis
        # --------------------------------------------------

        risk_result = RiskService.calculate(analysis)

        analysis["risk_score"] = risk_result["risk_score"]
        analysis["verdict"] = risk_result["verdict"]
        analysis["severity"] = risk_result["severity"]
        analysis["risk_factors"] = risk_result["risk_factors"]

        analysis["gate_applied"] = risk_result["gate_applied"]
        analysis["gate_reason"] = risk_result["gate_reason"]

        # --------------------------------------------------
        # 2. Confidence Analysis
        # --------------------------------------------------

        confidence_result = ConfidenceService.calculate(analysis)

        analysis["confidence_score"] = confidence_result[
            "confidence_score"
        ]

        analysis["confidence"] = confidence_result["confidence"]

        analysis["confidence_factors"] = confidence_result[
            "confidence_factors"
        ]

        analysis["confidence_metrics"] = confidence_result[
            "confidence_metrics"
        ]

        # --------------------------------------------------
        # 3. Recommendation Analysis
        # --------------------------------------------------

        recommendation_result = RecommendationService.generate(
            analysis
        )

        analysis["recommendation"] = recommendation_result[
            "recommendation"
        ]

        analysis["recommended_action"] = recommendation_result[
            "action"
        ]

        analysis["recommendation_priority"] = recommendation_result[
            "priority"
        ]

        # --------------------------------------------------
        # 4. SHADOW Report Engine
        # --------------------------------------------------

        report_engine = ReportEngine()
        report_schema = report_engine.build_report_schema(analysis)
        analysis["report"] = report_schema.model_dump()

        # --------------------------------------------------
        # Final SHADOW Analysis
        # --------------------------------------------------

        return analysis
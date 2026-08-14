from typing import Dict, Any


class RecommendationService:
    """
    SHADOW V1 Recommendation Engine.

    Generates actionable security recommendations, recommended actions,
    and priority based on normalized threat intelligence data.
    """

    @staticmethod
    def generate(normalized: Dict[str, Any]) -> Dict[str, Any]:
        verdict = normalized.get("verdict", "unknown")
        risk_score = normalized.get("risk_score")
        status = normalized.get("status")

        if status != "found":
            return {
                "recommendation": "No threat data found for this indicator. Treat as unverified.",
                "action": "Monitor & Gather Context",
                "priority": "LOW"
            }

        if verdict == "malicious" or (risk_score is not None and risk_score >= 70):
            return {
                "recommendation": "High risk threat indicator detected. Immediate isolation and remediation recommended.",
                "action": "Isolate & Block",
                "priority": "HIGH"
            }
        elif verdict == "suspicious" or (risk_score is not None and risk_score >= 40):
            return {
                "recommendation": "Suspicious indicator identified. Perform detailed behavioral analysis and monitor system activity.",
                "action": "Investigate & Monitor",
                "priority": "MEDIUM"
            }
        elif verdict == "clean":
            return {
                "recommendation": "Indicator appears clean based on available threat intelligence sources.",
                "action": "No Action Required",
                "priority": "LOW"
            }
        else:
            return {
                "recommendation": "Insufficient evidence to determine verdict conclusively.",
                "action": "Gather Additional Intelligence",
                "priority": "LOW"
            }

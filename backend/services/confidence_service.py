from typing import Dict, Any


class ConfidenceService:
    """
    SHADOW V1 Confidence Engine.

    Confidence measures the reliability and completeness
    of available threat-intelligence evidence.

    Confidence != Risk.

    Maximum Score: 100

    Factors:
        Vendor Coverage        -> 25
        Consensus Clarity      -> 25
        Evidence Completeness  -> 25
        Community Validation   -> 25
    """

    @staticmethod
    def calculate(normalized: Dict[str, Any]) -> Dict[str, Any]:

        # --------------------------------------------------
        # Unknown Handling
        # --------------------------------------------------

        if normalized.get("status") != "found":
            return {
                "confidence_score": None,
                "confidence": "unknown",
                "confidence_factors": [],
                "confidence_metrics": {}
            }

        score = 0
        factors = []

        usable_engines = normalized.get("usable_engines", 0)

        malicious = normalized.get(
            "malicious_detections",
            0
        )

        suspicious = normalized.get(
            "suspicious_detections",
            0
        )

        flagged = malicious + suspicious

        # --------------------------------------------------
        # 1. Vendor Coverage — MAX 25
        # --------------------------------------------------

        if usable_engines < 20:
            coverage_score = 5

        elif usable_engines <= 40:
            coverage_score = 15

        elif usable_engines <= 60:
            coverage_score = 20

        else:
            coverage_score = 25

        score += coverage_score

        factors.append(
            f"{usable_engines} usable security engines "
            f"contributed analysis (+{coverage_score})."
        )

        # --------------------------------------------------
        # 2. Consensus Clarity — MAX 25
        # --------------------------------------------------

        if usable_engines > 0:
            detection_percentage = (
                flagged / usable_engines
            ) * 100
        else:
            detection_percentage = 0.0

        if detection_percentage == 0:
            consensus_score = 25

        elif detection_percentage <= 5:
            consensus_score = 10

        elif detection_percentage <= 20:
            consensus_score = 15

        elif detection_percentage <= 50:
            consensus_score = 20

        else:
            consensus_score = 25

        score += consensus_score

        factors.append(
            f"{flagged}/{usable_engines} usable engines "
            f"flagged the indicator "
            f"({detection_percentage:.2f}%) "
            f"(+{consensus_score})."
        )

        # --------------------------------------------------
        # 3. Evidence Completeness — MAX 25
        # --------------------------------------------------

        evidence_score = 0
        evidence_present = []

        if normalized.get("threat_label"):
            evidence_score += 8
            evidence_present.append("threat label")

        if normalized.get("threat_categories"):
            evidence_score += 7
            evidence_present.append("threat category")

        if normalized.get("tags"):
            evidence_score += 5
            evidence_present.append("tags")

        # reputation = 0 is valid provider evidence
        if normalized.get("reputation") is not None:
            evidence_score += 5
            evidence_present.append("reputation")

        score += evidence_score

        if evidence_present:
            factors.append(
                "Threat intelligence metadata available: "
                + ", ".join(evidence_present)
                + f" (+{evidence_score})."
            )
        else:
            factors.append(
                "Limited threat-intelligence metadata available (+0)."
            )

        # --------------------------------------------------
        # 4. Community Validation — MAX 25
        # --------------------------------------------------

        times_submitted = normalized.get("times_submitted")

        community_score = 0

        if times_submitted is None:
            factors.append(
                "Submission-history data unavailable (+0)."
            )

        elif times_submitted <= 0:
            factors.append(
                "No previous submission history available (+0)."
            )

        elif times_submitted <= 2:
            community_score = 5

        elif times_submitted <= 10:
            community_score = 15

        else:
            community_score = 25

        if times_submitted is not None and times_submitted > 0:
            factors.append(
                f"Indicator has been submitted "
                f"{times_submitted} time(s) "
                f"(+{community_score})."
            )

        score += community_score

        # --------------------------------------------------
        # Defensive Cap
        # --------------------------------------------------

        confidence_score = min(score, 100)

        # --------------------------------------------------
        # Confidence Band
        # --------------------------------------------------

        if confidence_score >= 80:
            confidence = "high"

        elif confidence_score >= 50:
            confidence = "medium"

        elif confidence_score >= 20:
            confidence = "low"

        else:
            confidence = "very_low"

        # --------------------------------------------------
        # Final Result
        # --------------------------------------------------

        return {
            "confidence_score": confidence_score,
            "confidence": confidence,

            "confidence_factors": factors,

            "confidence_metrics": {
                "usable_engines": usable_engines,
                "flagged_engines": flagged,
                "detection_percentage": round(
                    detection_percentage,
                    2
                ),
                "times_submitted": times_submitted
            }
        }
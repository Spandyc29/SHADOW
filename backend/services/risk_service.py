from typing import Dict, Any


class RiskService:
    """
    SHADOW V1 Risk Engine.

    Calculates an explainable heuristic risk score for
    File / Hash threat-intelligence results.

    IMPORTANT:
    - This service does NOT call VirusTotal.
    - This service does NOT normalize provider data.
    - Risk score is NOT malware probability.
    - Confidence is calculated separately.
    - Provider evidence and SHADOW interpretation remain separate.
    """

    MAX_SCORE = 100

    # --------------------------------------------------
    # Known Malicious Threat Categories
    # --------------------------------------------------

    MALICIOUS_CATEGORIES = {
        "trojan",
        "ransomware",
        "worm",
        "backdoor",
        "rootkit",
        "spyware",
        "stealer",
        "dropper",
        "loader",
        "botnet",
        "malware",
    }

    # --------------------------------------------------
    # Suspicious Technical / Behavioral Tags
    # --------------------------------------------------

    SUSPICIOUS_TAGS = {
        "obfuscated",
        "packed",
        "anti-vm",
        "anti-debug",
        "evasive",
    }

    @staticmethod
    def calculate(normalized: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate SHADOW V1 risk assessment.

        Returns:
            {
                "risk_score": int | None,
                "verdict": str,
                "severity": str,
                "risk_factors": list[str]
            }
        """

        status = normalized.get("status")

        # ==================================================
        # 0. UNKNOWN / UNAVAILABLE INTELLIGENCE
        # ==================================================

        if status != "found":
            return {
                "risk_score": None,
                "verdict": "unknown",
                "severity": "unknown",
                "risk_factors": [
                    "Threat intelligence lookup did not return a usable result."
                ],
                "gate_applied": False,
                "gate_reason": None,
            }

        score = 0
        risk_factors = []

        # ==================================================
        # 1. DETECTION EVIDENCE
        # Maximum: 60 points
        # ==================================================

        detections = normalized.get("detections") or 0

        if detections >= 11:
            detection_points = 60

        elif detections >= 5:
            detection_points = 40

        elif detections >= 3:
            detection_points = 20

        elif detections == 2:
            detection_points = 10

        elif detections == 1:
            detection_points = 5

        else:
            detection_points = 0

        score += detection_points

        if detections > 0:
            risk_factors.append(
                f"{detections} security engine(s) flagged the indicator."
            )

        # ==================================================
        # 2. CLASSIFICATION EVIDENCE
        # Maximum: 15 points
        #
        # Threat label and category are related evidence.
        # Category therefore acts only as confirmation.
        # ==================================================

        threat_label = normalized.get("threat_label")

        threat_categories = normalized.get(
            "threat_categories",
            []
        ) or []

        category_values = {
            str(category.get("value", "")).lower()
            for category in threat_categories
            if isinstance(category, dict)
        }

        matched_categories = (
            category_values
            & RiskService.MALICIOUS_CATEGORIES
        )

        if threat_label:
            score += 10

            risk_factors.append(
                f"Threat intelligence classified it as '{threat_label}'."
            )

        if matched_categories:
            score += 5

            risk_factors.append(
                "Malicious classification confirmed by category: "
                + ", ".join(sorted(matched_categories))
                + "."
            )

        # ==================================================
        # 3. SUSPICIOUS TAG EVIDENCE
        # Maximum: 10 points
        #
        # Each matching tag = +3
        # Maximum contribution = 10
        # ==================================================

        tags = {
            str(tag).lower()
            for tag in (normalized.get("tags") or [])
        }

        matched_tags = (
            tags
            & RiskService.SUSPICIOUS_TAGS
        )

        tag_points = min(
            len(matched_tags) * 3,
            10
        )

        score += tag_points

        if matched_tags:
            risk_factors.append(
                "Suspicious characteristics detected: "
                + ", ".join(sorted(matched_tags))
                + "."
            )

        # ==================================================
        # 4. PROVIDER REPUTATION
        # Maximum: 5 points
        # ==================================================

        reputation = normalized.get("reputation")

        negative_reputation = (
            isinstance(reputation, (int, float))
            and not isinstance(reputation, bool)
            and reputation < 0
        )

        if negative_reputation:
            score += 5

            risk_factors.append(
                "Threat intelligence provider reports negative reputation."
            )

        # ==================================================
        # 5. FINAL SCORE
        # ==================================================

        score = min(
            score,
            RiskService.MAX_SCORE
        )

        # ==================================================
        # 6. CLEAN SAFETY CONDITION
        #
        # CLEAN requires explicit supporting conditions.
        # A low numerical score alone is NOT enough.
        # ==================================================

        clean_conditions_met = (
            detections == 0
            and not matched_categories
            and not negative_reputation
        )

        # ==================================================
        # 7. VERDICT + SEVERITY
        #
        # MALICIOUS QUALITY GATE:
        # Minimum 5 detections required before SHADOW
        # can issue a MALICIOUS verdict in V1.
        # ==================================================

        gate_applied = False
        gate_reason = None

        if clean_conditions_met and score < 20:
            verdict = "clean"
            severity = "low"

        elif detections >= 5 and score >= 80:
            verdict = "malicious"
            severity = "critical"

        elif detections >= 5 and score >= 50:
            verdict = "malicious"
            severity = "high"

        elif score >= 50 and detections < 5:
            # Quality gate: score warrants malicious but
            # insufficient detection consensus.
            verdict = "suspicious"
            severity = "high"
            gate_applied = True
            gate_reason = (
                f"Score ({score}) meets malicious threshold but only "
                f"{detections} engine(s) flagged it (minimum 5 required)."
            )

        else:
            verdict = "suspicious"

            if score >= 50:
                severity = "high"

            elif score >= 20:
                severity = "medium"

            else:
                severity = "low"

        # ==================================================
        # 8. FINAL RESULT
        # ==================================================

        return {
            "risk_score": score,
            "verdict": verdict,
            "severity": severity,
            "risk_factors": risk_factors,
            "gate_applied": gate_applied,
            "gate_reason": gate_reason,
        }
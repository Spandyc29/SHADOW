from typing import Dict
from datetime import datetime, timezone


def _valid_unix_timestamp(value):
    if isinstance(value, bool) or value in (None, ""):
        return None

    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return None

    if timestamp <= 0:
        return None

    try:
        year = datetime.fromtimestamp(timestamp, timezone.utc).year
    except (OSError, OverflowError, ValueError):
        return None

    if year <= 1970:
        return None

    return timestamp


def get_reputation_label(reputation) -> str:
    if reputation is None:
        return "Not Available"
    try:
        rep = int(reputation)
        if rep >= 500:
            return "Excellent"
        elif rep >= 100:
            return "Good"
        elif rep >= 0:
            return "Neutral"
        else:
            return "Poor"
    except (TypeError, ValueError):
        return "Not Available"


class ThreatNormalizer:
    """
    Converts provider-specific threat intelligence responses
    into SHADOW's canonical internal format.

    IMPORTANT:
    This class DOES NOT perform:
    - Threat detection
    - Risk scoring
    - Severity calculation
    - Confidence calculation
    - Recommendations

    It only translates provider data into
    SHADOW's standardized structure.
    """

    @staticmethod
    def normalize_hash_result(
        hash_value: str,
        vt_result: Dict
    ) -> Dict:

        # --------------------------------------------------
        # Provider Status
        # --------------------------------------------------

        status = vt_result.get("status")

        # --------------------------------------------------
        # Base Canonical Result
        # --------------------------------------------------

        normalized = {
            "indicator": hash_value,
            "indicator_type": "hash",

            # Provider / Lookup Status
            "status": status,

            # Detection Statistics
            "detections": vt_result.get("detections", 0),
            "total_engines": vt_result.get("total_engines", 0),
                 # --------------------------------------------------
# Engine Coverage
# Used by SHADOW Confidence Engine
# --------------------------------------------------

"malicious_detections": vt_result.get(
    "malicious_detections",
    0
),

"suspicious_detections": vt_result.get(
    "suspicious_detections",
    0
),

"usable_engines": vt_result.get(
    "usable_engines",
    0
),

"unusable_engines": vt_result.get(
    "unusable_engines",
    0
),

"unusable_breakdown": vt_result.get(
    "unusable_breakdown",
    {}
),
            # --------------------------------------------------
            # Threat Context
            # --------------------------------------------------

            "threat_label": vt_result.get("threat_label"),
            "threat_categories": vt_result.get(
                "threat_categories",
                []
            ),

            # --------------------------------------------------
            # Detection Evidence
            # --------------------------------------------------

            "flagged_engines": vt_result.get(
                "flagged_engines",
                []
            ),

            # --------------------------------------------------
            # Timeline
            # --------------------------------------------------

            "first_seen": _valid_unix_timestamp(
                vt_result.get("first_seen")
            ),
            "last_analysis": _valid_unix_timestamp(
                vt_result.get("last_analysis")
            ),

            # --------------------------------------------------
            # Associated File Information
            # --------------------------------------------------

            "meaningful_name": vt_result.get("meaningful_name"),

            "associated_names": vt_result.get(
                "associated_names",
                []
            ),

            "file_type": vt_result.get("file_type"),
            "file_size": vt_result.get("file_size"),

            # --------------------------------------------------
            # Additional Threat Intelligence
            # --------------------------------------------------

            "tags": vt_result.get("tags", []),
            "reputation": vt_result.get("reputation"),
            "reputation_label": get_reputation_label(vt_result.get("reputation")),
            "times_submitted": vt_result.get("times_submitted"),
            # --------------------------------------------------
            # Provider Evidence
            # --------------------------------------------------

            "permalink": vt_result.get("permalink"),
            "raw": vt_result.get("raw"),

            # --------------------------------------------------
            # SHADOW Analysis
            # Calculated by other services later.
            # --------------------------------------------------

            "severity": None,
            "confidence": None,
            "recommendation": None,
            "threat": None,
        }

        return normalized

    @staticmethod
    def normalize_url_result(
        url_value: str,
        vt_result: Dict
    ) -> Dict:

        normalized = ThreatNormalizer.normalize_hash_result(
            url_value,
            vt_result
        )

        normalized["indicator_type"] = "url"
        normalized["community_reputation"] = vt_result.get(
            "community_reputation",
            vt_result.get("reputation")
        )
        normalized["community_reputation_label"] = get_reputation_label(
            normalized.get("community_reputation")
        )

        return normalized

    @staticmethod
    def normalize_domain_result(
        domain_value: str,
        vt_result: Dict
    ) -> Dict:

        normalized = ThreatNormalizer.normalize_hash_result(
            domain_value,
            vt_result
        )

        normalized["indicator_type"] = "domain"
        normalized["community_reputation"] = vt_result.get(
            "community_reputation",
            vt_result.get("reputation")
        )
        normalized["reputation_label"] = get_reputation_label(
            vt_result.get("reputation")
        )
        normalized["community_reputation_label"] = get_reputation_label(
            normalized.get("community_reputation")
        )

        return normalized

    @staticmethod
    def normalize_ip_result(
        ip_value: str,
        vt_result: Dict
    ) -> Dict:

        normalized = ThreatNormalizer.normalize_hash_result(
            ip_value,
            vt_result
        )

        normalized["indicator_type"] = "ip"
        normalized["community_reputation"] = vt_result.get(
            "community_reputation",
            vt_result.get("reputation")
        )
        normalized["reputation_label"] = get_reputation_label(
            vt_result.get("reputation")
        )
        normalized["community_reputation_label"] = get_reputation_label(
            normalized.get("community_reputation")
        )

        normalized["country"] = vt_result.get("country")
        normalized["asn"] = vt_result.get("asn")
        normalized["network"] = vt_result.get("network")
        normalized["as_owner"] = vt_result.get("as_owner")
        normalized["whois"] = vt_result.get("whois")
        normalized["jarm"] = vt_result.get("jarm")
        normalized["last_https_certificate"] = vt_result.get(
            "last_https_certificate"
        )

        return normalized


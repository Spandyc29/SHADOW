from typing import Dict, Any, List
from services.report_engine.models.report_schema import TimelineSchema
from services.report_engine.generators.fivew1h import format_timestamp, format_file_type


class TimelineGenerator:
    """
    ⭐ SHADOW Timeline Generator.

    Generates a deterministic investigation timeline representing the SHADOW
    analysis workflow sequence (NO AI, NO External APIs).
    """

    def generate(self, data: Dict[str, Any]) -> TimelineSchema:
        raw_metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        raw_risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
        raw_confidence = data.get("confidence") if isinstance(data.get("confidence"), dict) else {}

        indicator_type = (
            data.get("indicator_type")
            or data.get("target_type")
            or raw_metadata.get("target_type")
            or "file"
        )
        indicator_type = str(indicator_type).lower().strip()

        raw_indicator = (
            data.get("indicator")
            or data.get("target_name")
            or data.get("file_name")
            or data.get("url")
            or data.get("domain")
            or data.get("ip")
            or data.get("hash")
            or raw_metadata.get("filename", "Security Target")
        )

        scan_ts_raw = data.get("created_at") or data.get("timestamp") or data.get("last_analysis")
        scan_ts = format_timestamp(scan_ts_raw)
        if scan_ts == "Not Available":
            scan_ts = "Timestamp Not Available"

        first_seen_raw = data.get("first_seen")
        first_seen_ts = format_timestamp(first_seen_raw) if first_seen_raw else None
        if first_seen_ts == "Not Available":
            first_seen_ts = None

        verdict = str(data.get("verdict") or raw_risk.get("classification") or "unclassified").upper()
        severity = str(raw_risk.get("level") or data.get("severity") or data.get("risk_level") or "low").upper()
        risk_score = raw_risk.get("score", data.get("risk_score", 0))

        confidence_score = raw_confidence.get("score", data.get("confidence_score", 0))
        confidence = str(raw_confidence.get("level") or data.get("confidence") or "neutral").upper()

        recommendation = data.get("recommendation") or "Review scan results and monitor indicator."
        recommended_action = data.get("recommended_action") or data.get("action") or "Investigate"

        detections = data.get("detections", 0) or 0
        total_engines = data.get("total_engines", 0) or 0

        raw_events = []

        # --------------------------------------------------
        # Step 1: Indicator Submission
        # --------------------------------------------------
        if indicator_type == "file":
            assoc_names = data.get("associated_names") or []
            file_name = data.get("file_name") or data.get("filename") or (assoc_names[0] if assoc_names else None) or raw_indicator
            f_type = format_file_type(data.get("file_type") or raw_metadata.get("file_type"), str(file_name))
            desc = f"User submitted a {f_type} artifact ('{file_name}') for investigation."
        elif indicator_type == "hash":
            assoc_names = data.get("associated_names") or []
            if assoc_names:
                desc = f"Cryptographic file hash '{raw_indicator}' (associated with '{assoc_names[0]}') submitted for investigation."
            else:
                desc = f"Cryptographic file hash '{raw_indicator}' submitted for investigation."
        elif indicator_type == "url":
            desc = f"Web URL '{data.get('url') or raw_indicator}' submitted for reputation analysis."
        elif indicator_type == "domain":
            desc = f"Registered domain '{data.get('domain') or raw_indicator}' submitted for DNS intelligence."
        elif indicator_type == "ip":
            desc = f"Network IP '{data.get('ip') or raw_indicator}' submitted for threat investigation."
        else:
            desc = f"Security target '{raw_indicator}' submitted for investigation."

        raw_events.append({
            "title": "Indicator Submitted",
            "timestamp": scan_ts,
            "description": desc
        })

        # --------------------------------------------------
        # Step 2: Historical Intelligence (If first_seen present)
        # --------------------------------------------------
        if first_seen_ts:
            raw_events.append({
                "title": "First Seen in Threat Intelligence",
                "timestamp": first_seen_ts,
                "description": f"Earliest recorded threat intelligence detection for target '{raw_indicator}'."
            })

        # --------------------------------------------------
        # Step 3: Threat Intelligence Lookup
        # --------------------------------------------------
        if detections > 0:
            if total_engines > 0:
                ti_desc = f"Queried threat intelligence providers. Recorded {detections} engine detections out of {total_engines} engines."
            else:
                ti_desc = f"Queried threat intelligence providers. Recorded {detections} engine detections."
        else:
            if total_engines > 0:
                ti_desc = f"Queried threat intelligence providers. No malicious flags recorded across {total_engines} engines."
            else:
                ti_desc = "Queried threat intelligence providers. No malicious flags recorded."

        raw_events.append({
            "title": "Threat Intelligence Lookup",
            "timestamp": scan_ts,
            "description": ti_desc
        })

        # --------------------------------------------------
        # Step 4: Risk Engine Evaluation
        # --------------------------------------------------
        raw_events.append({
            "title": "Risk Engine Evaluation",
            "timestamp": scan_ts,
            "description": f"Calculated Risk Score ({risk_score}/100) with Verdict '{verdict}' and Severity '{severity}'."
        })

        # --------------------------------------------------
        # Step 5: Confidence Engine Evaluation
        # --------------------------------------------------
        raw_events.append({
            "title": "Confidence Engine Evaluation",
            "timestamp": scan_ts,
            "description": f"Evaluated evidence quality and engine coverage. Assigned Confidence Score ({confidence_score}/100) with Level '{confidence}'."
        })

        # --------------------------------------------------
        # Step 6: Recommendation Engine Action
        # --------------------------------------------------
        raw_events.append({
            "title": "Recommendation Engine Action",
            "timestamp": scan_ts,
            "description": f"Generated Security Recommendation: '{recommendation}' (Action: {recommended_action})."
        })

        # --------------------------------------------------
        # Step 7: Report Engine Generation
        # --------------------------------------------------
        raw_events.append({
            "title": "Report Engine Generation",
            "timestamp": scan_ts,
            "description": "Compiled 5W1H schema, executive summary, IOC breakdown, and investigation timeline."
        })

        # --------------------------------------------------
        # Number Steps Sequentially
        # --------------------------------------------------
        final_events = []
        for idx, item in enumerate(raw_events, start=1):
            final_events.append({
                "step": idx,
                "title": item["title"],
                "timestamp": item["timestamp"],
                "description": item["description"]
            })

        return TimelineSchema(events=final_events)

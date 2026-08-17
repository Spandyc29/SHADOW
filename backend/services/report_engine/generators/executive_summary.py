from typing import Dict, Any, List
from services.report_engine.models.report_schema import ExecutiveSummarySchema


def format_file_type_label(raw_file_type: Any, file_name: str = "") -> str:
    """Helper to return a readable file type label."""
    ext_hint = ""
    if file_name and "." in file_name:
        ext_hint = file_name.split(".")[-1].lower()

    if isinstance(raw_file_type, dict):
        ft_type = (raw_file_type.get("type") or ext_hint).lower()
        ft_cat = (raw_file_type.get("category") or "").lower()
        if "apk" in ft_type or "android" in ft_cat or ext_hint == "apk":
            return "Android Package (APK)"
        elif "exe" in ft_type or "win32" in ft_cat or ext_hint == "exe" or "pe" in ft_type:
            return "Windows Executable (EXE)"
        elif "pdf" in ft_type or ext_hint == "pdf":
            return "PDF Document"
        elif ft_type in ["zip", "rar", "7z", "tar", "gz"] or ext_hint in ["zip", "rar", "7z", "tar", "gz"]:
            return "Compressed Archive"
        else:
            return f"{ft_type.upper()} File" if ft_type else "Binary File"
    elif isinstance(raw_file_type, str) and raw_file_type and raw_file_type != "N/A":
        lower = raw_file_type.lower()
        if "apk" in lower or ext_hint == "apk":
            return "Android Package (APK)"
        elif "exe" in lower or "executable" in lower or ext_hint == "exe":
            return "Windows Executable (EXE)"
        elif "pdf" in lower or ext_hint == "pdf":
            return "PDF Document"
        elif "zip" in lower or ext_hint == "zip":
            return "ZIP Archive"
        return raw_file_type.title()

    if ext_hint:
        if ext_hint == "apk":
            return "Android Package (APK)"
        elif ext_hint == "exe":
            return "Windows Executable (EXE)"
        elif ext_hint == "pdf":
            return "PDF Document"
        elif ext_hint == "zip":
            return "ZIP Archive"
        return f"{ext_hint.upper()} File"

    return "Binary File Artifact"


class ExecutiveSummaryGenerator:
    """
    ⭐ SHADOW Executive Summary Generator.

    Generates a deterministic, rule-based SOC investigation executive summary
    from normalized analysis objects (NO AI used).
    """

    def generate(self, data: Dict[str, Any]) -> ExecutiveSummarySchema:
        raw_metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        raw_risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
        raw_confidence = data.get("confidence") if isinstance(data.get("confidence"), dict) else {}

        indicator_type = (
            data.get("indicator_type")
            or data.get("target_type")
            or raw_metadata.get("target_type")
            or data.get("type", "file")
        )
        indicator_type = str(indicator_type).lower().strip()

        verdict_str = (
            data.get("verdict")
            or raw_risk.get("classification")
            or "unclassified"
        )
        verdict = str(verdict_str).title()

        # Safe Risk Score parsing
        raw_risk_score = raw_risk.get("score") if isinstance(raw_risk, dict) else None
        if raw_risk_score is None:
            raw_risk_score = data.get("risk_score")
        try:
            risk_score = int(raw_risk_score) if raw_risk_score is not None else 0
        except (ValueError, TypeError):
            risk_score = 0

        risk_max = (
            raw_risk.get("risk_max")
            or raw_risk.get("max_score")
            or data.get("risk_max")
            or data.get("max_score")
            or 90
        )

        raw_risk_level = raw_risk.get("level") or data.get("severity") or data.get("risk_level")
        if not raw_risk_level:
            if risk_score >= 80:
                risk_level = "High"
            elif risk_score >= 40:
                risk_level = "Medium"
            elif risk_score > 0:
                risk_level = "Low"
            else:
                risk_level = "Low"
        else:
            risk_level = str(raw_risk_level).title()

        # Safe Confidence Score parsing
        raw_conf_score = raw_confidence.get("score") if isinstance(raw_confidence, dict) else None
        if raw_conf_score is None:
            raw_conf_score = data.get("confidence_score")
        try:
            confidence_score = int(raw_conf_score) if raw_conf_score is not None else 0
        except (ValueError, TypeError):
            confidence_score = 0

        confidence_level_str = raw_confidence.get("level", data.get("confidence", "NEUTRAL"))
        confidence_level = str(confidence_level_str).title()

        detections = data.get("detections", 0) or 0
        total_engines = data.get("total_engines", 0) or 0
        threat_label = data.get("threat_label")

        tags_raw = data.get("tags") or []
        clean_tags = []
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if isinstance(t, str) and t.strip():
                    clean_tags.append(t.strip())
                elif isinstance(t, dict):
                    clean_tags.append(str(t.get("name") or t.get("tag") or ""))
        clean_tags = [t for t in clean_tags if t]

        associated_names = data.get("associated_names") or []
        assoc_name = None
        if isinstance(associated_names, list) and len(associated_names) > 0 and associated_names[0]:
            assoc_name = str(associated_names[0])

        file_name = (
            data.get("file_name")
            or data.get("filename")
            or assoc_name
            or data.get("indicator")
            or "Uploaded File"
        )

        file_type_label = format_file_type_label(
            data.get("file_type") or raw_metadata.get("file_type"),
            str(file_name)
        )

        # --------------------------------------------------
        # Build Summary Paragraph (Type-Aware)
        # --------------------------------------------------
        sentences = []

        if indicator_type == "file":
            sentences.append(
                f"The submitted {file_type_label} artifact '{file_name}' was analyzed by the SHADOW investigation pipeline."
            )
            sentences.append(
                f"The sample was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            if detections > 0:
                t_info = f" labeled as '{threat_label}'" if threat_label else ""
                sentences.append(
                    f"Threat intelligence identified {detections} security engine detections{t_info}."
                )
            elif clean_tags:
                sentences.append(
                    f"Threat intelligence identified behavioral tags ({', '.join(clean_tags[:4])})."
                )
            else:
                sentences.append(
                    "No malicious security engine detections were recorded for this file."
                )

            if verdict in ["Malicious", "Suspicious"] or risk_score >= 50:
                sentences.append("Analyst review and endpoint containment are recommended before execution.")
            else:
                sentences.append("Continuous security monitoring is recommended.")

        elif indicator_type == "hash":
            raw_hash = str(data.get("indicator") or data.get("hash") or "Submitted Hash")
            if assoc_name:
                sentences.append(
                    f"The cryptographic file hash '{raw_hash}' (associated with artifact '{assoc_name}') was evaluated against the SHADOW threat intelligence database."
                )
            else:
                sentences.append(
                    f"The cryptographic file hash '{raw_hash}' was evaluated against the SHADOW threat intelligence database."
                )
            sentences.append(
                f"The hash was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            if detections > 0:
                t_info = f" labeled as '{threat_label}'" if threat_label else ""
                sentences.append(
                    f"Threat intelligence identified {detections} security engine detections{t_info}."
                )
            elif clean_tags:
                sentences.append(
                    f"Threat intelligence identified threat tags ({', '.join(clean_tags[:4])})."
                )
            else:
                sentences.append(
                    "No threat intelligence engine flags were recorded for this hash."
                )

            if verdict in ["Malicious", "Suspicious"] or risk_score >= 50:
                sentences.append("Egress blocking and host hash-matching scans are recommended.")
            else:
                sentences.append("Standard threat monitoring is recommended.")

        elif indicator_type == "url":
            raw_url = str(data.get("url") or data.get("indicator") or "Submitted URL")
            sentences.append(
                f"The submitted web URL '{raw_url}' was analyzed by the SHADOW web security investigation pipeline."
            )
            sentences.append(
                f"The URL target was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            if detections > 0:
                sentences.append(
                    f"Threat intelligence identified {detections} security engine detections flagging potential web threat indicators."
                )
            elif clean_tags:
                sentences.append(
                    f"Threat intelligence identified web indicators ({', '.join(clean_tags[:4])})."
                )
            else:
                sentences.append(
                    "No malicious detections were recorded for this web resource."
                )

            if verdict in ["Malicious", "Suspicious"] or risk_score >= 50:
                sentences.append("Web gateway blocking and proxy log audit are recommended.")
            else:
                sentences.append("Standard web gateway security policies apply.")

        elif indicator_type == "domain":
            raw_domain = str(data.get("domain") or data.get("indicator") or "Registered Domain")
            resolved_ip = data.get("resolved_ip") or data.get("ip")
            isp = data.get("isp") or data.get("registrar")

            sentences.append(
                f"The registered domain '{raw_domain}' was evaluated by the SHADOW network intelligence engine."
            )
            sentences.append(
                f"The domain was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            if resolved_ip:
                isp_info = f" ({isp})" if isp else ""
                sentences.append(
                    f"DNS intelligence resolved this domain to IP address {resolved_ip}{isp_info}."
                )
            elif detections > 0:
                sentences.append(
                    f"Domain intelligence query returned {detections} threat engine detections."
                )
            else:
                sentences.append(
                    "No malicious domain flags were recorded."
                )

            if verdict in ["Malicious", "Suspicious"] or risk_score >= 50:
                sentences.append("DNS sinkholing and perimeter firewall filtering are recommended.")
            else:
                sentences.append("Routine DNS monitoring is recommended.")

        elif indicator_type == "ip":
            raw_ip = str(data.get("ip") or data.get("indicator") or "Target IP Address")
            isp = data.get("isp") or data.get("org")
            country = data.get("country") or data.get("geo_location")

            sentences.append(
                f"The network IP address '{raw_ip}' was analyzed for security risk and threat intelligence indicators."
            )
            sentences.append(
                f"The host was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            if isp:
                loc_info = f" ({country})" if country and country != "Not Applicable" else ""
                sentences.append(
                    f"Host infrastructure belongs to {isp}{loc_info} with {detections} engine detections."
                )
            elif detections > 0:
                sentences.append(
                    f"Network threat intelligence recorded {detections} security engine flags."
                )
            else:
                sentences.append(
                    "No malicious flags were recorded for this IP address."
                )

            if verdict in ["Malicious", "Suspicious"] or risk_score >= 50:
                sentences.append("Firewall egress blocking and SIEM correlation are recommended.")
            else:
                sentences.append("Standard network monitoring applies.")

        else:
            sentences.append(
                f"The security target was analyzed by the SHADOW investigation pipeline."
            )
            sentences.append(
                f"The target was classified as {verdict} with a {risk_level} Risk Score ({risk_score}/{risk_max}) and {confidence_level} Confidence ({confidence_score}/100)."
            )
            sentences.append("Standard security monitoring applies.")

        summary_text = " ".join(sentences)

        # --------------------------------------------------
        # Build Key Findings List (Type-Aware)
        # --------------------------------------------------
        findings = [
            f"Verdict: {verdict}",
            f"Risk Level: {risk_level} (Score: {risk_score}/{risk_max})",
            f"Confidence: {confidence_level} (Score: {confidence_score}/100)",
        ]

        if detections > 0:
            if total_engines > 0:
                findings.append(f"{detections}/{total_engines} detection engines flagged the target")
            else:
                findings.append(f"{detections} detection engines flagged the target")
        else:
            findings.append("0 engine detections recorded")

        # Type-specific key findings
        if indicator_type == "file":
            findings.append(f"File Format: {file_type_label}")
            if data.get("file_size"):
                findings.append(f"File Size: {data.get('file_size')} bytes")
        elif indicator_type == "hash":
            if assoc_name:
                findings.append(f"Associated Name: {assoc_name}")
            raw_hash = str(data.get("indicator") or data.get("hash") or "")
            if raw_hash:
                findings.append(f"Hash Signature: {raw_hash[:16]}...")
        elif indicator_type == "url":
            url_info = data.get("url_info") if isinstance(data.get("url_info"), dict) else {}
            domain_name = url_info.get("domain") or data.get("domain")
            if domain_name:
                findings.append(f"Target Domain: {domain_name}")
        elif indicator_type == "domain":
            resolved_ip = data.get("resolved_ip") or data.get("ip")
            if resolved_ip:
                findings.append(f"Resolved IP: {resolved_ip}")
            isp = data.get("isp") or data.get("registrar")
            if isp:
                findings.append(f"ISP/Registrar: {isp}")
        elif indicator_type == "ip":
            isp = data.get("isp") or data.get("org")
            if isp:
                findings.append(f"ISP/Network: {isp}")
            country = data.get("country") or data.get("geo_location")
            if country and country != "Not Applicable":
                findings.append(f"Geo Location: {country}")

        if threat_label:
            findings.append(f"Threat Classification: {threat_label}")
        elif clean_tags:
            findings.append(f"Behavior Tags: {', '.join(clean_tags[:4])}")

        return ExecutiveSummarySchema(
            summary_text=summary_text,
            key_findings=findings
        )

from typing import Dict, Any, List
from datetime import datetime, timezone
from services.report_engine.models.report_schema import FiveW1HSchema


def format_timestamp(val: Any) -> str:
    """Converts unix timestamp or ISO string into human readable UTC string YYYY-MM-DD HH:MM:SS UTC."""
    if val is None or val == "" or val == "N/A" or val == "null":
        return "Not Available"
    if isinstance(val, (int, float)):
        try:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "Not Available"
    val_str = str(val).strip()
    if val_str.endswith(" UTC"):
        return val_str
    if val_str.replace(".", "", 1).isdigit():
        try:
            ts_num = float(val_str)
            dt = datetime.fromtimestamp(ts_num, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "Not Available"
    try:
        iso_str = val_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    return val_str if val_str else "Not Available"


def format_file_type(raw_file_type: Any, file_name: str = "", mime_type: str = "") -> str:
    """Generates human-readable file format string."""
    ext_hint = ""
    if file_name and "." in file_name:
        ext_hint = file_name.split(".")[-1].lower()

    if isinstance(raw_file_type, dict):
        ft_type = (raw_file_type.get("type") or ext_hint).lower()
        ft_cat = (raw_file_type.get("category") or "").lower()
        if "apk" in ft_type or "android" in ft_cat or ext_hint == "apk":
            return "Android Package (.apk)"
        elif "exe" in ft_type or "win32" in ft_cat or ext_hint == "exe" or "pe" in ft_type:
            return "Windows Executable (.exe)"
        elif "pdf" in ft_type or ext_hint == "pdf":
            return "PDF Document (.pdf)"
        elif ft_type in ["zip", "rar", "7z", "tar", "gz"] or ext_hint in ["zip", "rar", "7z", "tar", "gz"]:
            return f"Compressed Archive (.{ft_type or ext_hint})"
        else:
            name = ft_type.upper() if ft_type else "Binary"
            return f"{name} File"
    elif isinstance(raw_file_type, str) and raw_file_type and raw_file_type != "N/A":
        lower = raw_file_type.lower()
        if "apk" in lower or ext_hint == "apk":
            return "Android Package (.apk)"
        elif "exe" in lower or "executable" in lower or "pe32" in lower or ext_hint == "exe":
            return "Windows Executable (.exe)"
        elif "pdf" in lower or ext_hint == "pdf":
            return "PDF Document (.pdf)"
        elif "zip" in lower or ext_hint == "zip":
            return "ZIP Archive (.zip)"
        return raw_file_type.title()

    if ext_hint:
        if ext_hint == "apk":
            return "Android Package (.apk)"
        elif ext_hint == "exe":
            return "Windows Executable (.exe)"
        elif ext_hint == "pdf":
            return "PDF Document (.pdf)"
        elif ext_hint == "zip":
            return "ZIP Archive (.zip)"
        return f"{ext_hint.upper()} File (.{ext_hint})"

    return "Binary File / Unknown Format"


def is_hash_string(val: str) -> bool:
    """Checks if string is MD5 (32), SHA1 (40), or SHA256 (64) hex hash."""
    if not val:
        return False
    val_clean = str(val).strip().lower()
    return len(val_clean) in (32, 40, 64) and all(c in "0123456789abcdef" for c in val_clean)


def extract_hashes(data: Dict[str, Any], indicator: str) -> Dict[str, str]:
    """Builds clean MD5, SHA1, SHA256 hashes dict."""
    hashes = data.get("hashes") if isinstance(data.get("hashes"), dict) else {}
    md5 = data.get("md5") or hashes.get("md5") or "Not Available"
    sha1 = data.get("sha1") or hashes.get("sha1") or "Not Available"
    sha256 = data.get("sha256") or hashes.get("sha256") or "Not Available"

    if is_hash_string(indicator):
        ind_len = len(indicator.strip())
        if ind_len == 32 and md5 == "Not Available":
            md5 = indicator.strip()
        elif ind_len == 40 and sha1 == "Not Available":
            sha1 = indicator.strip()
        elif ind_len == 64 and sha256 == "Not Available":
            sha256 = indicator.strip()

    return {
        "md5": md5 if md5 != "N/A" else "Not Available",
        "sha1": sha1 if sha1 != "N/A" else "Not Available",
        "sha256": sha256 if sha256 != "N/A" else "Not Available",
    }


def extract_attack_vectors(data: Dict[str, Any]) -> List[str]:
    """Extracts attack vectors with priority: VT tags > Behavioral > Category > Metadata."""
    vectors = []

    # 1. VirusTotal / Intelligence Tags
    tags = data.get("tags") or []
    if isinstance(tags, list) and tags:
        clean_tags = []
        for t in tags:
            if isinstance(t, str) and t.strip():
                clean_tags.append(t.strip())
            elif isinstance(t, dict):
                val = t.get("name") or t.get("tag") or str(t)
                clean_tags.append(str(val))
        if clean_tags:
            vectors.append(f"Threat Tags: {', '.join(clean_tags)}")

    # 2. Behavioral / Category / Classification
    threat_label = data.get("threat_label")
    threat_cat = data.get("threat_category") or data.get("threat_categories")
    behaviord = data.get("behavioral_indicators") or []

    def extract_clean_str(v: Any) -> str:
        if isinstance(v, dict):
            return str(v.get("value") or v.get("category") or v.get("name") or v.get("tag") or v.get("label") or "").strip()
        return str(v or "").strip()

    if threat_label:
        lbl_str = extract_clean_str(threat_label)
        if lbl_str:
            vectors.append(f"Threat Label: {lbl_str}")
    if threat_cat:
        if isinstance(threat_cat, list) and threat_cat:
            cat_strs = [extract_clean_str(c) for c in threat_cat if extract_clean_str(c)]
            if cat_strs:
                vectors.append(f"Threat Category: {', '.join(cat_strs)}")
        else:
            cat_str = extract_clean_str(threat_cat)
            if cat_str:
                vectors.append(f"Threat Category: {cat_str}")

    if isinstance(behaviord, list) and behaviord:
        for b in behaviord[:3]:
            b_str = str(b.get("name", b) if isinstance(b, dict) else b).strip()
            vectors.append(f"Behavioral Indicator: {b_str}")

    # 3. Explicit attack vectors if present
    raw_av = data.get("attack_vectors")
    if isinstance(raw_av, list):
        for v in raw_av:
            v_str = str(v.get("vector", v) if isinstance(v, dict) else v).strip()
            if v_str and v_str != "Direct Execution / Access Attempt" and v_str not in vectors:
                vectors.append(v_str)

    if not vectors:
        vectors.append("No attack vector information available.")

    return vectors


class FiveW1HGenerator:
    """
    SHADOW 5W1H Analysis Generator (V1).
    Transforms investigation findings into type-aware, human-readable 5W1H structure.
    """

    def generate(self, data: Dict[str, Any]) -> FiveW1HSchema:
        raw_metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        raw_risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
        raw_confidence = data.get("confidence") if isinstance(data.get("confidence"), dict) else {}
        raw_recommendations = data.get("recommendations") if isinstance(data.get("recommendations"), list) else []

        indicator_type = (
            data.get("indicator_type")
            or data.get("target_type")
            or raw_metadata.get("target_type")
            or data.get("type", "file")
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
            or raw_metadata.get("filename", "Unknown Artifact")
        )

        # --------------------------------------------------
        # 1. WHO (Context-aware Target Context)
        # --------------------------------------------------
        if indicator_type == "file":
            target_system = "Uploaded File"
            submitter = "Analyst / File Upload"
            affected_entity = "Target Endpoint / Asset"
        elif indicator_type == "hash":
            target_system = "Submitted Artifact"
            submitter = "Analyst / Hash Investigation"
            affected_entity = "Internal Infrastructure"
        elif indicator_type == "domain":
            target_system = "Registered Domain"
            submitter = "Analyst / Domain Query"
            affected_entity = "DNS Gateway / Network Perimeter"
        elif indicator_type == "ip":
            target_system = "Network Address"
            submitter = "Analyst / IP Lookup"
            affected_entity = "Perimeter Firewall / Host Network"
        elif indicator_type == "url":
            target_system = "Submitted URL"
            submitter = "Analyst / URL Investigation"
            affected_entity = "Web Gateway / Client Browser"
        else:
            target_system = "Security Target"
            submitter = "Analyst / System Process"
            affected_entity = "Internal Infrastructure"

        who = {
            "target_system": data.get("target_system") or target_system,
            "submitter": data.get("submitted_by") or submitter,
            "affected_entity": data.get("organization") or affected_entity,
            "target_category": indicator_type.upper(),
        }

        # --------------------------------------------------
        # 2. WHAT (Artifact & Threat)
        # --------------------------------------------------
        associated_names = data.get("associated_names") or []
        meaningful_name = None
        if data.get("file_name"):
            meaningful_name = data.get("file_name")
        elif data.get("filename"):
            meaningful_name = data.get("filename")
        elif isinstance(associated_names, list) and len(associated_names) > 0 and associated_names[0]:
            meaningful_name = associated_names[0]

        if indicator_type in ["file", "hash"]:
            artifact_name = meaningful_name or str(raw_indicator)
            if indicator_type == "file":
                artifact_type = format_file_type(
                    data.get("file_type") or raw_metadata.get("file_type"),
                    artifact_name,
                    raw_metadata.get("mime_type", "")
                )
            else:
                artifact_type = "Cryptographic File Hash"
                if meaningful_name:
                    artifact_type = f"File Hash ({format_file_type(data.get('file_type'), meaningful_name)})"
            hashes_dict = extract_hashes(data, str(raw_indicator))
            file_format = format_file_type(
                data.get("file_type") or raw_metadata.get("file_type"),
                artifact_name,
                raw_metadata.get("mime_type", "")
            )
            raw_mime = (
                data.get("mime_type")
                or raw_metadata.get("mime_type")
                or (data.get("file_type") if isinstance(data.get("file_type"), dict) else {}).get("mime")
                or "application/octet-stream"
            )
        elif indicator_type == "url":
            artifact_name = data.get("url") or str(raw_indicator)
            artifact_type = "Web URL / Link"
            hashes_dict = "Not Applicable"
            file_format = "Web Resource (HTTP/HTTPS)"
            raw_mime = "text/html"
        elif indicator_type == "domain":
            artifact_name = data.get("domain") or str(raw_indicator)
            artifact_type = "Internet Domain Name"
            hashes_dict = "Not Applicable"
            file_format = "DNS Domain Name"
            raw_mime = "Not Applicable"
        elif indicator_type == "ip":
            artifact_name = data.get("ip") or str(raw_indicator)
            artifact_type = "IPv4 / IPv6 Address"
            hashes_dict = "Not Applicable"
            file_format = "Network Host Address"
            raw_mime = "Not Applicable"
        else:
            artifact_name = str(raw_indicator)
            artifact_type = "Security Artifact"
            hashes_dict = "Not Applicable"
            file_format = "Unknown Format"
            raw_mime = "Not Applicable"

        what = {
            "artifact_name": artifact_name,
            "artifact_type": artifact_type,
            "threat_classification": raw_risk.get("classification") or data.get("verdict") or "UNCLASSIFIED",
            "hashes": hashes_dict,
            "file_size_bytes": data.get("file_size") or raw_metadata.get("size") or "Not Applicable",
            "file_format": file_format,
            "mime_type": raw_mime,
        }

        # --------------------------------------------------
        # 3. WHERE (Location & Path)
        # --------------------------------------------------
        if indicator_type in ["file", "hash"]:
            location_path = data.get("file_path") or "Not Available"
            network_destination = "Not Applicable"
            geo_location = "Not Applicable"
            registrar_or_isp = "Not Applicable"
        elif indicator_type == "url":
            url_info = data.get("url_info") if isinstance(data.get("url_info"), dict) else {}
            location_path = url_info.get("path") or data.get("url") or str(raw_indicator)
            network_destination = url_info.get("domain") or data.get("domain") or data.get("ip") or "Not Available"
            geo_location = data.get("geo_location") or data.get("country") or "Not Available"
            registrar_or_isp = data.get("isp") or data.get("registrar") or "Not Available"
        elif indicator_type == "domain":
            location_path = "Not Applicable"
            network_destination = data.get("resolved_ip") or data.get("ip") or artifact_name
            geo_location = data.get("geo_location") or data.get("country") or "Not Available"
            registrar_or_isp = data.get("registrar") or data.get("isp") or "Not Available"
        elif indicator_type == "ip":
            location_path = "Not Applicable"
            network_destination = artifact_name
            geo_location = data.get("geo_location") or data.get("country") or data.get("asn") or "Not Available"
            registrar_or_isp = data.get("isp") or data.get("org") or data.get("asn") or "Not Available"
        else:
            location_path = "Not Applicable"
            network_destination = "Not Applicable"
            geo_location = "Not Applicable"
            registrar_or_isp = "Not Applicable"

        where = {
            "target_identifier": artifact_name,
            "location_path": location_path,
            "network_destination": network_destination,
            "geo_location": geo_location,
            "registrar_or_isp": registrar_or_isp,
        }

        # --------------------------------------------------
        # 4. WHEN (Human Readable Timestamps)
        # --------------------------------------------------
        scan_ts = format_timestamp(data.get("created_at") or data.get("timestamp") or data.get("last_analysis"))
        first_seen_ts = format_timestamp(data.get("first_seen"))
        last_seen_ts = format_timestamp(data.get("last_seen") or data.get("last_analysis"))

        when = {
            "scan_timestamp": scan_ts,
            "analysis_duration": data.get("analysis_duration") or "Instantaneous",
            "first_seen": first_seen_ts,
            "last_seen": last_seen_ts,
        }

        # --------------------------------------------------
        # 5. WHY (Severity & Rationale)
        # --------------------------------------------------
        risk_score = raw_risk.get("score", data.get("risk_score", 0))
        risk_level = str(raw_risk.get("level", data.get("severity", data.get("risk_level", "LOW")))).upper()
        confidence_score = raw_confidence.get("score", data.get("confidence_score", 0))
        confidence_level = str(raw_confidence.get("level", data.get("confidence", "NEUTRAL"))).upper()

        risk_factors = raw_risk.get("factors") or data.get("risk_factors") or ["No specific risk factors flagged."]
        risk_max = raw_risk.get("risk_max") or raw_risk.get("max_score") or data.get("risk_max") or data.get("max_score") or 90

        why = {
            "risk_score": risk_score,
            "risk_max": risk_max,
            "risk_level": risk_level,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "severity_rationale": raw_risk.get("rationale") or data.get("summary") or f"Verdict: {data.get('verdict', 'unclassified')}. Evaluated against SHADOW risk rules.",
            "risk_factors": risk_factors,
        }

        # --------------------------------------------------
        # 6. HOW (Vectors & Recommendations)
        # --------------------------------------------------
        attack_vectors = extract_attack_vectors(data)

        recs = raw_recommendations
        if not recs:
            if data.get("recommendation"):
                recs = [data.get("recommendation")]
                if data.get("recommended_action"):
                    recs.append(f"Action: {data.get('recommended_action')}")
            else:
                if indicator_type in ["file", "hash"]:
                    recs = [
                        "Isolate the file artifact if risk score is HIGH.",
                        "Perform an endpoint anti-malware scan across host machines.",
                        "Block matching file hash signatures on EDR endpoints."
                    ]
                elif indicator_type in ["url", "domain"]:
                    recs = [
                        "Block domain/URL in perimeter web gateway and DNS resolver.",
                        "Inspect proxy logs for HTTP requests to this destination.",
                        "Notify users who attempted to access this link."
                    ]
                elif indicator_type == "ip":
                    recs = [
                        "Block IP address on external firewalls and perimeter routers.",
                        "Inspect network traffic logs for connections to this host.",
                        "Correlate IP activity with SIEM security alerts."
                    ]
                else:
                    recs = [
                        "Isolate target if risk score is HIGH.",
                        "Review IOC matches and block malicious indicators.",
                        "Perform full endpoint scan."
                    ]

        how = {
            "attack_vectors": attack_vectors,
            "behavioral_indicators": data.get("behavioral_indicators") or ["Not Available"],
            "iocs_found": data.get("iocs") or ["Not Available"],
            "recommendations": recs
        }

        return FiveW1HSchema(
            who=who,
            what=what,
            where=where,
            when=when,
            why=why,
            how=how
        )

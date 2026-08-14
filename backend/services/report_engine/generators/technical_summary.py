from typing import Dict, Any, List
from services.report_engine.models.report_schema import TechnicalSummarySchema
from services.report_engine.generators.fivew1h import format_timestamp, format_file_type, extract_hashes, extract_attack_vectors


def add_section_if_valid(details: Dict[str, Any], section_name: str, content: Dict[str, Any]):
    """
    Adds a section to details only if it contains at least one piece of meaningful data.
    Omits the section completely if all values are default placeholders.
    """
    has_valid_data = False
    for v in content.values():
        v_str = str(v).strip()
        if v_str and v_str not in ["Not Available", "Not Applicable", "None Flagged", "None Identified", "N/A", "0"]:
            has_valid_data = True
            break

    if has_valid_data:
        details[section_name] = content


class TechnicalSummaryGenerator:
    """
    ⭐ SHADOW Technical Summary Generator.

    Generates structured, category-based technical summary data for SOC & DFIR analysts.
    (NO AI, NO External APIs, NO Risk Calculation).
    """

    def generate(self, data: Dict[str, Any]) -> TechnicalSummarySchema:
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

        details: Dict[str, Any] = {}

        # --------------------------------------------------
        # 1. General Information (Always Present)
        # --------------------------------------------------
        scan_ts = format_timestamp(data.get("created_at") or data.get("timestamp") or data.get("last_analysis"))
        verdict = str(data.get("verdict") or raw_risk.get("classification") or "UNCLASSIFIED").upper()
        risk_level = str(raw_risk.get("level") or data.get("severity") or data.get("risk_level") or "LOW").upper()

        details["General Information"] = {
            "Indicator Type": indicator_type.upper(),
            "Target": str(raw_indicator),
            "Scan Timestamp": scan_ts,
            "Verdict": verdict,
            "Risk Level": risk_level,
            "Confidence": str(raw_confidence.get("level") or data.get("confidence") or "NEUTRAL").upper()
        }

        # --------------------------------------------------
        # 2. Hashes Section
        # --------------------------------------------------
        if indicator_type in ["file", "hash"] or data.get("hashes") or data.get("md5") or data.get("sha256"):
            hashes_dict = extract_hashes(data, str(raw_indicator))
            add_section_if_valid(details, "Hashes", {
                "MD5": hashes_dict.get("md5", "Not Available"),
                "SHA1": hashes_dict.get("sha1", "Not Available"),
                "SHA256": hashes_dict.get("sha256", "Not Available"),
                "SHA512": data.get("sha512") or "Not Available"
            })

        # --------------------------------------------------
        # 3. File Information Section
        # --------------------------------------------------
        if indicator_type in ["file", "hash"] or data.get("file_name") or data.get("file_size"):
            assoc_names = data.get("associated_names") or []
            file_name = data.get("file_name") or data.get("filename") or (assoc_names[0] if assoc_names else None) or "Not Available"
            file_size = data.get("file_size") or raw_metadata.get("size")
            file_size_str = f"{file_size} bytes" if file_size else "Not Available"
            mime_type = data.get("mime_type") or raw_metadata.get("mime_type") or "Not Available"
            f_type = format_file_type(data.get("file_type") or raw_metadata.get("file_type"), str(file_name))
            ext = file_name.split(".")[-1] if isinstance(file_name, str) and "." in file_name else "Not Available"

            add_section_if_valid(details, "File Information", {
                "File Name": str(file_name),
                "File Size": file_size_str,
                "MIME Type": str(mime_type),
                "File Type": f_type,
                "Extension": f".{ext}" if ext != "Not Available" else "Not Available"
            })

        # --------------------------------------------------
        # 4. Network Information Section
        # --------------------------------------------------
        if indicator_type in ["url", "domain", "ip"] or data.get("resolved_ip") or data.get("isp"):
            url_info = data.get("url_info") if isinstance(data.get("url_info"), dict) else {}
            net_info = {
                "IP Address": data.get("ip") or data.get("resolved_ip") or "Not Available",
                "Domain": data.get("domain") or url_info.get("domain") or "Not Available",
                "URL": data.get("url") or "Not Available",
                "ASN": data.get("asn") or "Not Available",
                "ISP": data.get("isp") or data.get("org") or "Not Available",
                "Country": data.get("country") or data.get("geo_location") or "Not Available",
                "Reverse DNS": data.get("reverse_dns") or "Not Available"
            }
            add_section_if_valid(details, "Network Information", net_info)

        # --------------------------------------------------
        # 5. WHOIS Information Section
        # --------------------------------------------------
        whois_data = data.get("whois") if isinstance(data.get("whois"), dict) else {}
        registrar = data.get("registrar") or whois_data.get("registrar") or "Not Available"
        reg_date = format_timestamp(whois_data.get("created_date") or data.get("registration_date"))
        exp_date = format_timestamp(whois_data.get("expiration_date") or data.get("expiration_date"))

        ns_list = whois_data.get("nameservers") or data.get("nameservers") or []
        ns_str = ", ".join(ns_list) if isinstance(ns_list, list) and ns_list else "Not Available"

        whois_info = {
            "Registrar": registrar,
            "Registration Date": reg_date,
            "Expiration Date": exp_date,
            "Name Servers": ns_str
        }
        add_section_if_valid(details, "WHOIS Information", whois_info)

        # --------------------------------------------------
        # 6. DNS Information Section
        # --------------------------------------------------
        dns_data = data.get("dns") if isinstance(data.get("dns"), dict) else {}
        dns_info = {
            "A Records": ", ".join(dns_data.get("a", [])) if isinstance(dns_data.get("a"), list) and dns_data.get("a") else "Not Available",
            "AAAA Records": ", ".join(dns_data.get("aaaa", [])) if isinstance(dns_data.get("aaaa"), list) and dns_data.get("aaaa") else "Not Available",
            "MX Records": ", ".join(dns_data.get("mx", [])) if isinstance(dns_data.get("mx"), list) and dns_data.get("mx") else "Not Available",
            "NS Records": ", ".join(dns_data.get("ns", [])) if isinstance(dns_data.get("ns"), list) and dns_data.get("ns") else "Not Available",
            "TXT Records": ", ".join(dns_data.get("txt", [])) if isinstance(dns_data.get("txt"), list) and dns_data.get("txt") else "Not Available",
        }
        add_section_if_valid(details, "DNS Information", dns_info)

        # --------------------------------------------------
        # 7. Threat Intelligence Section
        # --------------------------------------------------
        detections = data.get("detections", 0) or 0
        total_engines = data.get("total_engines", 0) or 0
        det_ratio = f"{detections}/{total_engines}" if total_engines > 0 else f"{detections} detections"

        tags_raw = data.get("tags") or []
        clean_tags = []
        if isinstance(tags_raw, list):
            for t in tags_raw:
                if isinstance(t, str) and t.strip():
                    clean_tags.append(t.strip())
                elif isinstance(t, dict):
                    clean_tags.append(str(t.get("name") or t.get("tag") or ""))
        clean_tags = [t for t in clean_tags if t]

        threat_cat = data.get("threat_category") or data.get("threat_categories") or []
        cat_strs = []
        if isinstance(threat_cat, list):
            cat_strs = [str(c.get("category", c) if isinstance(c, dict) else c).strip() for c in threat_cat]
        elif isinstance(threat_cat, str):
            cat_strs = [threat_cat]

        ti_info = {
            "Detection Ratio": det_ratio,
            "Reputation Score": str(data.get("reputation", "Not Available")),
            "Tags": ", ".join(clean_tags) if clean_tags else "None Flagged",
            "Categories": ", ".join(cat_strs) if cat_strs else "None Flagged"
        }
        add_section_if_valid(details, "Threat Intelligence", ti_info)

        # --------------------------------------------------
        # 8. Certificates Section
        # --------------------------------------------------
        cert_data = data.get("certificates") or data.get("ssl_cert")
        cert_dict = cert_data if isinstance(cert_data, dict) else {}
        cert_info = {
            "JARM Hash": data.get("jarm") or cert_dict.get("jarm") or "Not Available",
            "HTTPS Certificate": cert_dict.get("issuer") or (cert_data if isinstance(cert_data, str) else "Not Available"),
            "SSL Information": cert_dict.get("subject") or "Not Available"
        }
        add_section_if_valid(details, "Certificates", cert_info)

        # --------------------------------------------------
        # 9. Behavior Section
        # --------------------------------------------------
        behaviord = data.get("behavioral_indicators") or []
        beh_strs = []
        if isinstance(behaviord, list):
            beh_strs = [str(b.get("name", b) if isinstance(b, dict) else b).strip() for b in behaviord]

        av_list = extract_attack_vectors(data)

        raw_iocs = data.get("iocs") or []
        ioc_count_str = str(len(raw_iocs)) if isinstance(raw_iocs, list) and raw_iocs else "0"

        behavior_info = {
            "Behavioral Indicators": ", ".join(beh_strs) if beh_strs else "None Identified",
            "Attack Vectors": ", ".join(av_list) if av_list else "None Identified",
            "IOC Count": ioc_count_str
        }
        add_section_if_valid(details, "Behavior", behavior_info)

        return TechnicalSummarySchema(details=details)

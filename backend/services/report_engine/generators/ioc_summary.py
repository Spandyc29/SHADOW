import re
from typing import Dict, Any, List, Tuple
from services.report_engine.models.report_schema import IOCSummarySchema

# Preferred sorting order for IOC types
TYPE_ORDER = {
    "SHA256": 1,
    "SHA1": 2,
    "MD5": 3,
    "SHA512": 4,
    "IP": 5,
    "Domain": 6,
    "URL": 7,
    "Email": 8,
    "File Name": 9,
    "File Path": 10,
    "Registry Key": 11,
    "Mutex": 12,
    "Certificate": 13,
}

KNOWN_FILE_EXTENSIONS = {
    "exe", "dll", "apk", "sys", "bin", "elf", "scr", "vbs", "ps1", "bat", "cmd",
    "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "7z", "tar", "gz", "iso"
}


def classify_and_normalize_ioc(val: Any, explicit_type: str = None) -> Tuple[str, str]:
    """
    Classifies raw string into standard IOC type and normalizes its format.
    """
    if val is None:
        return None, None

    val_clean = str(val).strip()
    if not val_clean or val_clean in ["N/A", "Not Available", "Not Applicable", "null", "None"]:
        return None, None

    lower_val = val_clean.lower()

    # Explicit override if specified
    if explicit_type:
        exp_clean = str(explicit_type).strip().title()
        if exp_clean in ["File Name", "File Path", "Registry Key", "Mutex", "Certificate", "Domain", "IP", "URL"]:
            if exp_clean in ["Domain", "Email", "SHA256", "SHA1", "MD5", "SHA512"]:
                return exp_clean, lower_val
            return exp_clean, val_clean

    # Hashes
    if len(val_clean) == 64 and re.fullmatch(r'^[a-fA-F0-9]{64}$', val_clean):
        return "SHA256", lower_val
    if len(val_clean) == 40 and re.fullmatch(r'^[a-fA-F0-9]{40}$', val_clean):
        return "SHA1", lower_val
    if len(val_clean) == 32 and re.fullmatch(r'^[a-fA-F0-9]{32}$', val_clean):
        return "MD5", lower_val
    if len(val_clean) == 128 and re.fullmatch(r'^[a-fA-F0-9]{128}$', val_clean):
        return "SHA512", lower_val

    # URLs
    if lower_val.startswith("http://") or lower_val.startswith("https://"):
        return "URL", val_clean

    # Email
    if re.fullmatch(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', val_clean):
        return "Email", lower_val

    # IP Address (IPv4 or IPv6 pattern)
    if re.fullmatch(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', val_clean) or re.fullmatch(r'^(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}$', val_clean):
        return "IP", val_clean

    # File Path
    if "\\" in val_clean or ("/" in val_clean and not lower_val.startswith("http")):
        return "File Path", val_clean

    # File Name check if extension matches known file extensions
    ext_hint = val_clean.split(".")[-1].lower() if "." in val_clean else ""
    if ext_hint in KNOWN_FILE_EXTENSIONS:
        return "File Name", val_clean

    # Domain
    if re.fullmatch(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', val_clean):
        return "Domain", lower_val

    return "File Name", val_clean


class IOCSummaryGenerator:
    """
    ⭐ SHADOW IOC Summary Generator.

    Extracts, normalizes, classifies, and deduplicates Indicators of Compromise (IOCs)
    from normalized investigation objects (NO AI, NO External APIs).
    """

    def generate(self, data: Dict[str, Any]) -> IOCSummarySchema:
        raw_metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
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
        )

        extracted_items: List[Tuple[str, str, str]] = []  # List of (ioc_type, normalized_val, source)

        # 1. Primary User Submission Target
        if raw_indicator:
            explicit_t = None
            if indicator_type == "file":
                explicit_t = "File Name"
            elif indicator_type == "domain":
                explicit_t = "Domain"
            elif indicator_type == "ip":
                explicit_t = "IP"
            elif indicator_type == "url":
                explicit_t = "URL"

            ioc_type, norm_val = classify_and_normalize_ioc(raw_indicator, explicit_type=explicit_t)
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "User Submission"))

        # 2. File Hashes
        hashes_dict = data.get("hashes") if isinstance(data.get("hashes"), dict) else {}
        for h_key in ["sha256", "sha1", "md5", "sha512"]:
            h_val = data.get(h_key) or hashes_dict.get(h_key)
            if h_val:
                ioc_type, norm_val = classify_and_normalize_ioc(h_val)
                if ioc_type and norm_val:
                    extracted_items.append((ioc_type, norm_val, "File Metadata"))

        # 3. File Names & Associated Names
        if data.get("file_name"):
            ioc_type, norm_val = classify_and_normalize_ioc(data.get("file_name"), explicit_type="File Name")
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "File Metadata"))

        if data.get("filename"):
            ioc_type, norm_val = classify_and_normalize_ioc(data.get("filename"), explicit_type="File Name")
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "File Metadata"))

        associated_names = data.get("associated_names") or []
        if isinstance(associated_names, list):
            for name in associated_names:
                ioc_type, norm_val = classify_and_normalize_ioc(name, explicit_type="File Name")
                if ioc_type and norm_val:
                    extracted_items.append((ioc_type, norm_val, "Threat Intelligence"))

        # 4. File Paths
        file_path = data.get("file_path") or data.get("location_path")
        if file_path:
            ioc_type, norm_val = classify_and_normalize_ioc(file_path, explicit_type="File Path")
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "File Metadata"))

        # 5. Network Destinations / Resolved IPs / Domains / URLs
        resolved_ip = data.get("resolved_ip") or data.get("ip")
        if resolved_ip:
            ioc_type, norm_val = classify_and_normalize_ioc(resolved_ip, explicit_type="IP")
            if ioc_type and norm_val:
                source = "User Submission" if indicator_type == "ip" else "DNS"
                extracted_items.append((ioc_type, norm_val, source))

        resolved_domain = data.get("domain") or data.get("resolved_domain")
        if resolved_domain:
            ioc_type, norm_val = classify_and_normalize_ioc(resolved_domain, explicit_type="Domain")
            if ioc_type and norm_val:
                source = "User Submission" if indicator_type == "domain" else "DNS"
                extracted_items.append((ioc_type, norm_val, source))

        url_val = data.get("url")
        if url_val:
            ioc_type, norm_val = classify_and_normalize_ioc(url_val, explicit_type="URL")
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "User Submission" if indicator_type == "url" else "Threat Intelligence"))

        url_info = data.get("url_info") if isinstance(data.get("url_info"), dict) else {}
        if url_info.get("domain"):
            ioc_type, norm_val = classify_and_normalize_ioc(url_info.get("domain"), explicit_type="Domain")
            if ioc_type and norm_val:
                extracted_items.append((ioc_type, norm_val, "Threat Intelligence"))

        # 6. Raw IOCs array inside analysis object
        raw_iocs = data.get("iocs") or []
        if isinstance(raw_iocs, list):
            for item in raw_iocs:
                if isinstance(item, dict):
                    raw_val = item.get("value") or item.get("indicator")
                    src = item.get("source") or "Threat Intelligence"
                    explicit_t = item.get("type")
                    ioc_type, norm_val = classify_and_normalize_ioc(raw_val, explicit_type=explicit_t)
                    if ioc_type and norm_val:
                        extracted_items.append((ioc_type, norm_val, src))
                elif isinstance(item, str):
                    ioc_type, norm_val = classify_and_normalize_ioc(item)
                    if ioc_type and norm_val:
                        extracted_items.append((ioc_type, norm_val, "Threat Intelligence"))

        # 7. Behavioral sub-arrays (Registry Keys, Mutexes, Certificates)
        reg_keys = data.get("registry_keys") or []
        if isinstance(reg_keys, list):
            for rk in reg_keys:
                ioc_type, norm_val = classify_and_normalize_ioc(rk, explicit_type="Registry Key")
                if ioc_type and norm_val:
                    extracted_items.append((ioc_type, norm_val, "Behavioral Indicators"))

        mutexes = data.get("mutexes") or []
        if isinstance(mutexes, list):
            for mx in mutexes:
                ioc_type, norm_val = classify_and_normalize_ioc(mx, explicit_type="Mutex")
                if ioc_type and norm_val:
                    extracted_items.append((ioc_type, norm_val, "Behavioral Indicators"))

        certs = data.get("certificates") or data.get("ssl_cert") or []
        if isinstance(certs, list):
            for cert in certs:
                ioc_type, norm_val = classify_and_normalize_ioc(cert, explicit_type="Certificate")
                if ioc_type and norm_val:
                    extracted_items.append((ioc_type, norm_val, "Threat Intelligence"))

        # --------------------------------------------------
        # Deduplication (Preserve Insertion Order)
        # --------------------------------------------------
        seen = set()
        deduped_iocs: List[Dict[str, str]] = []

        for ioc_type, norm_val, source in extracted_items:
            key = (ioc_type, norm_val)
            if key not in seen:
                seen.add(key)
                deduped_iocs.append({
                    "type": ioc_type,
                    "value": norm_val,
                    "source": source
                })

        # --------------------------------------------------
        # Sorting (Group by preferred IOC type order)
        # --------------------------------------------------
        deduped_iocs.sort(key=lambda item: (TYPE_ORDER.get(item["type"], 99), item["value"]))

        return IOCSummarySchema(iocs=deduped_iocs)

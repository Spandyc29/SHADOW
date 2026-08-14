import httpx
from datetime import datetime, timezone
from config import VT_API_KEY
from services.url_service import get_url_identifier


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


from typing import Optional


async def check_hash(hash_value: str, api_key: Optional[str] = None) -> dict:
    """
    Look up a file hash on VirusTotal and extract
    threat-intelligence data required by SHADOW.
    """

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    headers = {
        "x-apikey": api_key or VT_API_KEY
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, headers=headers)

    # --------------------------------------------------
    # Provider Status Handling
    # --------------------------------------------------

    if response.status_code == 404:
        return {
            "status": "not_found"
        }

    if response.status_code == 429:
        return {
            "status": "rate_limited"
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "code": response.status_code
        }

    # --------------------------------------------------
    # VirusTotal Response
    # --------------------------------------------------

    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    analysis_results = attributes.get(
        "last_analysis_results",
        {}
    )

    # --------------------------------------------------
    # Detection & Engine Coverage Statistics
    # --------------------------------------------------

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    type_unsupported = stats.get("type-unsupported", 0)
    failure = stats.get("failure", 0)
    timeout = stats.get("timeout", 0)
    confirmed_timeout = stats.get("confirmed-timeout", 0)

    # All engine result states reported by VirusTotal
    total_engines = sum(stats.values())

    # Engines that actually produced a usable analysis result
    usable_engines = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    unusable_engines = total_engines - usable_engines

    unusable_breakdown = {
        "type_unsupported": type_unsupported,
        "failure": failure,
        "timeout": timeout,
        "confirmed_timeout": confirmed_timeout,
    }

    # --------------------------------------------------
    # Flagged Engines
    # --------------------------------------------------

    flagged_engines = []

    for engine_name, engine_data in analysis_results.items():

        category = engine_data.get("category")

        if category in {"malicious", "suspicious"}:
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "result": engine_data.get("result")
            })

    # --------------------------------------------------
    # Threat Classification
    # --------------------------------------------------

    popular_classification = attributes.get(
        "popular_threat_classification",
        {}
    )

    threat_label = popular_classification.get(
        "suggested_threat_label"
    )

    threat_categories = popular_classification.get(
        "popular_threat_category",
        []
    )

    # --------------------------------------------------
    # Associated File Information
    # --------------------------------------------------

    associated_names = attributes.get("names", [])

    meaningful_name = attributes.get("meaningful_name")

    file_type = (
        attributes.get("type_description")
        or attributes.get("type_tag")
    )

    file_size = attributes.get("size")

    # --------------------------------------------------
    # Timeline
    # --------------------------------------------------

    first_seen = _valid_unix_timestamp(
        attributes.get("first_submission_date")
    )

    last_analysis = (
        _valid_unix_timestamp(attributes.get("last_analysis_date"))
        or _valid_unix_timestamp(attributes.get("last_modification_date"))
    )

    # --------------------------------------------------
    # Additional Threat Intelligence
    # --------------------------------------------------

    tags = attributes.get("tags", [])

    reputation = attributes.get("reputation")
    times_submitted = attributes.get("times_submitted")
    # --------------------------------------------------
    # SHADOW Provider Response
    # --------------------------------------------------

    return {
        "status": "found",

        # Existing Risk Engine field
        "detections": malicious,

        # Detection counts for Confidence Engine
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,

        # Engine coverage
        "total_engines": total_engines,
        "usable_engines": usable_engines,
        "unusable_engines": unusable_engines,
        "unusable_breakdown": unusable_breakdown,

        "threat_label": threat_label,
        "threat_categories": threat_categories,

        "flagged_engines": flagged_engines,

        "first_seen": first_seen,
        "last_analysis": last_analysis,

        "meaningful_name": meaningful_name,
        "associated_names": associated_names,

        "file_type": file_type,
        "file_size": file_size,

        "tags": tags,
        "reputation": reputation,
        "times_submitted": times_submitted,
        "permalink": (
            f"https://www.virustotal.com/gui/file/{hash_value}"
        ),

        "raw": data,
    }


async def check_url(url_value: str, api_key: Optional[str] = None) -> dict:
    """
    Look up a URL on VirusTotal and extract provider intelligence.

    This function only maps provider data. SHADOW analysis engines run later.
    """

    url_id = get_url_identifier(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": api_key or VT_API_KEY
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return {
            "status": "not_found",
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        }

    if response.status_code == 429:
        return {
            "status": "rate_limited"
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "code": response.status_code
        }

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    analysis_results = attributes.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total_engines = sum(stats.values())
    usable_engines = malicious + suspicious + harmless + undetected
    unusable_engines = total_engines - usable_engines

    flagged_engines = []

    for engine_name, engine_data in analysis_results.items():
        category = engine_data.get("category")

        if category in {"malicious", "suspicious"}:
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "result": engine_data.get("result"),
            })

    categories = attributes.get("categories") or {}
    threat_categories = [
        {
            "engine": engine,
            "value": category,
        }
        for engine, category in categories.items()
    ]

    last_analysis = (
        _valid_unix_timestamp(attributes.get("last_analysis_date"))
        or _valid_unix_timestamp(attributes.get("last_modification_date"))
    )

    return {
        "status": "found",

        "detections": malicious,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,

        "total_engines": total_engines,
        "usable_engines": usable_engines,
        "unusable_engines": unusable_engines,
        "unusable_breakdown": {
            "timeout": timeout,
        },

        "threat_label": attributes.get("title"),
        "threat_categories": threat_categories,
        "flagged_engines": flagged_engines,

        "first_seen": None,
        "last_analysis": last_analysis,

        "meaningful_name": attributes.get("url"),
        "associated_names": [],

        "file_type": "URL",
        "file_size": None,

        "tags": attributes.get("tags", []),
        "reputation": attributes.get("reputation"),
        "times_submitted": attributes.get("times_submitted"),
        "community_reputation": attributes.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        "raw": data,
    }


async def check_domain(domain_value: str, api_key: Optional[str] = None) -> dict:
    """
    Look up a domain on VirusTotal and extract provider intelligence.
    """

    url = f"https://www.virustotal.com/api/v3/domains/{domain_value}"

    headers = {
        "x-apikey": api_key or VT_API_KEY
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return {
            "status": "not_found",
            "permalink": f"https://www.virustotal.com/gui/domain/{domain_value}",
        }

    if response.status_code == 429:
        return {
            "status": "rate_limited"
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "code": response.status_code
        }

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    analysis_results = attributes.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total_engines = sum(stats.values())
    usable_engines = malicious + suspicious + harmless + undetected
    unusable_engines = total_engines - usable_engines

    flagged_engines = []

    for engine_name, engine_data in analysis_results.items():
        category = engine_data.get("category")

        if category in {"malicious", "suspicious"}:
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "result": engine_data.get("result"),
            })

    categories = attributes.get("categories") or {}
    threat_categories = [
        {
            "engine": engine,
            "value": category,
        }
        for engine, category in categories.items()
    ]

    last_analysis = (
        _valid_unix_timestamp(attributes.get("last_analysis_date"))
        or _valid_unix_timestamp(attributes.get("last_modification_date"))
    )
    first_seen = _valid_unix_timestamp(attributes.get("creation_date"))

    return {
        "status": "found",

        "detections": malicious,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,

        "total_engines": total_engines,
        "usable_engines": usable_engines,
        "unusable_engines": unusable_engines,
        "unusable_breakdown": {
            "timeout": timeout,
        },

        "threat_label": None,
        "threat_categories": threat_categories,
        "flagged_engines": flagged_engines,

        "first_seen": first_seen,
        "last_analysis": last_analysis,

        "meaningful_name": domain_value,
        "associated_names": [],

        "file_type": "Domain",
        "file_size": None,

        "tags": attributes.get("tags", []),
        "reputation": attributes.get("reputation"),
        "times_submitted": None,
        "community_reputation": attributes.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/domain/{domain_value}",
        "raw": data,
    }


async def check_ip(ip_value: str, api_key: Optional[str] = None) -> dict:
    """
    Look up an IP address on VirusTotal and extract provider intelligence.
    """

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_value}"

    headers = {
        "x-apikey": api_key or VT_API_KEY
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return {
            "status": "not_found",
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_value}",
        }

    if response.status_code == 429:
        return {
            "status": "rate_limited"
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "code": response.status_code
        }

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    analysis_results = attributes.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total_engines = sum(stats.values())
    usable_engines = malicious + suspicious + harmless + undetected
    unusable_engines = total_engines - usable_engines

    flagged_engines = []

    for engine_name, engine_data in analysis_results.items():
        category = engine_data.get("category")

        if category in {"malicious", "suspicious"}:
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "result": engine_data.get("result"),
            })

    raw_categories = attributes.get("categories") or {}
    if isinstance(raw_categories, dict):
        threat_categories = [
            {
                "engine": engine,
                "value": cat_val,
            }
            for engine, cat_val in raw_categories.items()
        ]
    elif isinstance(raw_categories, list):
        threat_categories = raw_categories
    else:
        threat_categories = []

    last_analysis = (
        _valid_unix_timestamp(attributes.get("last_analysis_date"))
        or _valid_unix_timestamp(attributes.get("last_modification_date"))
    )

    return {
        "status": "found",

        "detections": malicious,
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,

        "total_engines": total_engines,
        "usable_engines": usable_engines,
        "unusable_engines": unusable_engines,
        "unusable_breakdown": {
            "timeout": timeout,
        },

        "threat_label": None,
        "threat_categories": threat_categories,
        "flagged_engines": flagged_engines,

        "first_seen": None,
        "last_analysis": last_analysis,

        "meaningful_name": ip_value,
        "associated_names": [],

        "file_type": "IP",
        "file_size": None,

        "tags": attributes.get("tags", []),
        "reputation": attributes.get("reputation"),
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "network": attributes.get("network"),
        "as_owner": attributes.get("as_owner"),
        "whois": attributes.get("whois"),
        "jarm": attributes.get("jarm"),
        "last_https_certificate": attributes.get("last_https_certificate"),
        "times_submitted": None,
        "community_reputation": attributes.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip_value}",
        "raw": data,
    }



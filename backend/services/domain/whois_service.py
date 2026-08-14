import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import whois
except ImportError:
    whois = None


logger = logging.getLogger("SHADOW")


def _extract_datetime(value: Any) -> Optional[datetime]:
    """
    Extract a valid UTC datetime object from datetime, list of datetimes, or date string.
    """

    if value is None:
        return None

    if isinstance(value, list):
        value = value[0] if value else None

    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, str):
        val_str = value.strip()
        if not val_str or val_str.lower() in ("null", "none", "not available", "[]"):
            return None
        try:
            from dateutil import parser
            dt = parser.parse(val_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    return None


def _format_date(value: Any) -> str:
    """
    Format WHOIS date into clean ISO format (YYYY-MM-DD HH:mm:ss UTC).
    Returns 'Not Available' if missing or invalid.
    """

    dt = _extract_datetime(value)
    if dt is None:
        if isinstance(value, str) and value.strip() and value.strip().lower() not in ("null", "none", "[]"):
            return value.strip()
        return "Not Available"

    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _calculate_domain_age(creation_date_val: Any) -> str:
    """
    Calculate Domain Age from Creation Date.
    Returns formatted string like '4 years, 3 months' or 'Not Available'.
    """

    dt = _extract_datetime(creation_date_val)
    if dt is None:
        return "Not Available"

    now = datetime.now(timezone.utc)
    if dt > now:
        return "Not Available"

    days = (now - dt).days
    if days < 0:
        return "Not Available"

    years = days // 365
    remaining_days = days % 365
    months = remaining_days // 30

    if years > 0:
        if months > 0:
            return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
        return f"{years} year{'s' if years != 1 else ''}"
    elif months > 0:
        return f"{months} month{'s' if months != 1 else ''}"
    else:
        return f"{days} day{'s' if days != 1 else ''}"


def _calculate_remaining_time(expiration_date_val: Any) -> str:
    """
    Calculate Remaining Time until Expiration.
    Returns formatted string like '1 year, 5 months' or 'Expired' or 'Not Available'.
    """

    dt = _extract_datetime(expiration_date_val)
    if dt is None:
        return "Not Available"

    now = datetime.now(timezone.utc)
    if dt < now:
        return "Expired"

    days = (dt - now).days
    if days < 0:
        return "Expired"

    years = days // 365
    remaining_days = days % 365
    months = remaining_days // 30

    if years > 0:
        if months > 0:
            return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
        return f"{years} year{'s' if years != 1 else ''}"
    elif months > 0:
        return f"{months} month{'s' if months != 1 else ''}"
    else:
        return f"{days} day{'s' if days != 1 else ''}"


def _as_list(value: Any) -> List[str]:
    """
    Always return a clean list.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return [str(v) for v in value if v]

    return [str(value)]


def _deduplicate_list(value: Any) -> List[str]:
    """
    Deduplicate strings case-insensitively while preserving insertion order.
    """

    raw_list = _as_list(value)
    seen = set()
    result = []
    for item in raw_list:
        clean = str(item).strip()
        if not clean or clean.lower() in ("null", "none"):
            continue
        lower_clean = clean.lower()
        if lower_clean not in seen:
            seen.add(lower_clean)
            result.append(clean)
    return result


def _clean_field(val: Any) -> str:
    """
    Return clean string value or 'Not Available'.
    """

    if val is None:
        return "Not Available"

    if isinstance(val, list):
        val = val[0] if val else None
        if val is None:
            return "Not Available"

    s = str(val).strip()
    if not s or s.lower() in ("null", "none", "[]", "not available"):
        return "Not Available"

    return s


def _format_dnssec(dnssec_val: Any) -> str:
    """
    Return 'Signed' or 'Unsigned'.
    """

    if dnssec_val is None:
        return "Unsigned"

    val_str = str(dnssec_val).strip().lower()
    if val_str in ("signed", "signeddelegation", "yes", "true", "1"):
        return "Signed"

    return "Unsigned"


async def lookup_whois(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup.

    Returns normalized WHOIS information.
    Never raises exceptions.
    """

    try:
        if whois is None:
            raise ImportError("whois module not installed")

        data = whois.whois(domain)

        creation_date = _format_date(data.creation_date)
        expiration_date = _format_date(data.expiration_date)
        updated_date = _format_date(data.updated_date)

        domain_age = _calculate_domain_age(data.creation_date)
        remaining_time = _calculate_remaining_time(data.expiration_date)

        return {
            "registrar": _clean_field(data.registrar),
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,

            "domain_age": domain_age,
            "remaining_time": remaining_time,

            "name_servers": _deduplicate_list(data.name_servers),
            "status": _deduplicate_list(data.status),

            "dnssec": _format_dnssec(data.dnssec),
            "country": _clean_field(data.country),
            "org": _clean_field(data.org),
            "emails": _deduplicate_list(data.emails),

            "available": True,
        }

    except Exception as e:
        logger.warning(f"[WHOIS] Lookup failed for {domain}: {e}")

        return {
            "registrar": "Not Available",
            "creation_date": "Not Available",
            "expiration_date": "Not Available",
            "updated_date": "Not Available",

            "domain_age": "Not Available",
            "remaining_time": "Not Available",

            "name_servers": [],
            "status": [],

            "dnssec": "Unsigned",
            "country": "Not Available",
            "org": "Not Available",
            "emails": [],

            "available": False,
        }
import asyncio
import logging
import socket
from typing import Any, Dict, Optional

from services.ip.ip_validator import get_ip_classification, normalize_ip

logger = logging.getLogger("SHADOW")


def get_reverse_dns(ip_address: str) -> Optional[str]:
    """
    Perform a reverse DNS (PTR) lookup for an IP address.
    Returns hostname string if found, None otherwise.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError) as exc:
        logger.debug(f"[PTR] Reverse DNS lookup failed for {ip_address}: {exc}")
        return None
    except Exception as exc:
        logger.warning(f"[PTR] Error during reverse DNS lookup for {ip_address}: {exc}")
        return None


async def get_ip_details(
    ip_address: str,
    vt_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Gather IP metadata adhering to Single Responsibility Principle:
    - Normalizes IP
    - Classifies IP features (IPv4/IPv6, Public/Private, Loopback, Multicast, Reserved, Link Local, Unspecified)
    - Performs reverse DNS PTR lookup asynchronously
    - Enriches with ASN / Geo details from provider lookup if available
    """
    normalized = normalize_ip(ip_address)
    classification = get_ip_classification(normalized)
    ptr_hostname = await asyncio.to_thread(get_reverse_dns, normalized)

    info = {
        "ip": normalized,
        "version": classification["version"],
        "ip_version": classification["ip_version"],
        "is_public": classification["is_public"],
        "is_private": classification["is_private"],
        "is_loopback": classification["is_loopback"],
        "is_multicast": classification["is_multicast"],
        "is_reserved": classification["is_reserved"],
        "is_link_local": classification["is_link_local"],
        "is_unspecified": classification["is_unspecified"],
        "reverse_dns": ptr_hostname,
    }

    if vt_result:
        info.update({
            "asn": vt_result.get("asn"),
            "as_owner": vt_result.get("as_owner"),
            "as_org": vt_result.get("as_owner"),
            "country": vt_result.get("country"),
            "city": vt_result.get("city"),
            "network": vt_result.get("network"),
        })

    return info

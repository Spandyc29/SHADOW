import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

from services.domain.domain_validator import normalize_domain, validate_domain
from services.domain.whois_service import lookup_whois

logger = logging.getLogger("SHADOW")


def resolve_dns(domain: str) -> Dict[str, Any]:
    """
    Perform DNS resolution for a domain.
    Returns resolved IP addresses and hostname aliases.
    """

    ip_addresses: List[str] = []
    aliases: List[str] = []

    try:
        canonical_name, aliases, ips = socket.gethostbyname_ex(domain)
        ip_addresses = ips
    except socket.gaierror as exc:
        logger.debug(f"[DNS] Failed to resolve {domain}: {exc}")
    except Exception as exc:
        logger.warning(f"[DNS] Error resolving {domain}: {exc}")

    return {
        "ip_addresses": ip_addresses,
        "aliases": aliases,
        "resolved": len(ip_addresses) > 0,
    }


def extract_domain_information(domain: str) -> Dict[str, Any]:
    """
    Extract structural domain metadata such as TLD, SLD, subdomains, and length.
    """

    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else parts[0]
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else None

    return {
        "domain": domain,
        "tld": tld,
        "second_level_domain": sld,
        "subdomain": subdomain,
        "domain_length": len(domain),
        "label_count": len(parts),
    }


async def get_domain_details(domain: str) -> Dict[str, Any]:
    """
    Orchestrate domain metadata gathering:
    - Domain normalization & validation
    - Structural extraction
    - DNS resolution
    - WHOIS lookup
    """

    normalized = normalize_domain(domain)
    info = extract_domain_information(normalized)

    dns_info = await asyncio.to_thread(resolve_dns, normalized)
    whois_info = await lookup_whois(normalized)

    return {
        "domain": normalized,
        "info": info,
        "dns": dns_info,
        "whois": whois_info,
    }

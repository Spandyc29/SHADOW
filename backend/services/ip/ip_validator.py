import ipaddress
from urllib.parse import urlparse


def normalize_ip(value: str) -> str:
    """
    Normalize an IP address string.
    Strips whitespace, extracts IP from URLs or bracketed notation if present,
    and returns a clean canonical IP string (IPv4 or IPv6).

    Raises ValueError if value is empty or invalid IP address.
    """
    if not value or not isinstance(value, str):
        raise ValueError("IP address cannot be empty.")

    candidate = value.strip()

    if not candidate:
        raise ValueError("IP address cannot be empty.")

    # Remove http:// or https:// scheme if present
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate

    # Remove enclosing brackets for IPv6 if present, e.g., [::1] or [::1]:80
    if candidate.startswith("["):
        end_bracket = candidate.find("]")
        if end_bracket != -1:
            candidate = candidate[1:end_bracket]

    # Handle IPv4 host:port format if not a valid IP directly
    if ":" in candidate and candidate.count(":") == 1:
        host, _ = candidate.split(":", 1)
        try:
            ip_obj = ipaddress.ip_address(host)
            return str(ip_obj)
        except ValueError:
            pass

    try:
        ip_obj = ipaddress.ip_address(candidate)
        return str(ip_obj)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def validate_ip(value: str) -> bool:
    """
    Returns True if value is a valid IPv4 or IPv6 address, False otherwise.
    """
    try:
        normalize_ip(value)
        return True
    except Exception:
        return False


def get_ip_classification(ip_str: str) -> dict:
    """
    Classify IP address properties:
    - version (IPv4 / IPv6)
    - public vs private
    - loopback
    - multicast
    - reserved
    - link local
    - unspecified
    """
    ip_obj = ipaddress.ip_address(ip_str)

    is_priv = ip_obj.is_private
    is_loop = ip_obj.is_loopback
    is_multi = ip_obj.is_multicast
    is_res = ip_obj.is_reserved
    is_ll = ip_obj.is_link_local
    is_unspec = ip_obj.is_unspecified

    # An IP address is public if it is global and not private, loopback, multicast, reserved, link-local, or unspecified
    is_pub = ip_obj.is_global and not (
        is_priv or is_loop or is_multi or is_res or is_ll or is_unspec
    )

    return {
        "version": f"IPv{ip_obj.version}",
        "ip_version": ip_obj.version,
        "is_public": is_pub,
        "is_private": is_priv,
        "is_loopback": is_loop,
        "is_multicast": is_multi,
        "is_reserved": is_res,
        "is_link_local": is_ll,
        "is_unspecified": is_unspec,
    }

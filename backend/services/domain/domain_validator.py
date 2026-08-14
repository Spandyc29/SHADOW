import re
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(value: str) -> str:
    """
    Normalize a domain or URL into a clean lowercase domain.

    Examples
    --------
    google.com
        -> google.com

    https://www.google.com/login
        -> google.com

    HTTP://Example.COM
        -> example.com
    """

    if not value:
        raise ValueError("Domain cannot be empty.")

    value = value.strip()

    # If URL missing scheme but contains slash
    if "://" not in value and "/" in value:
        value = "https://" + value

    # If plain domain
    if "://" not in value:
        host = value
    else:
        parsed = urlparse(value)
        host = parsed.hostname or ""

    host = host.lower().strip()

    # Remove www.
    if host.startswith("www."):
        host = host[4:]

    if not host:
        raise ValueError("Unable to determine domain.")

    if not DOMAIN_REGEX.fullmatch(host):
        raise ValueError(f"Invalid domain: {host}")

    return host


def validate_domain(value: str) -> bool:
    """
    Returns True if valid domain.
    """

    try:
        normalize_domain(value)
        return True
    except Exception:
        return False
import base64
from urllib.parse import urlparse


def get_url_identifier(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def extract_url_information(url: str) -> dict:
    parsed = urlparse(url)

    return {
        "protocol": parsed.scheme,
        "host": parsed.hostname,
        "path": parsed.path or "/",
        "query": parsed.query or None,
        "fragment": parsed.fragment or None,
        "port": parsed.port,
        "url_length": len(url),
        "domain": parsed.hostname,
    }

from urllib.parse import urlparse


def normalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("URL must be a string.")

    candidate = value.strip()

    if not candidate:
        raise ValueError("URL cannot be empty.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL must include a valid host.")

    if "." not in parsed.hostname:
        raise ValueError("URL host must include a domain or IP address.")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid.") from exc

    if any(char.isspace() for char in candidate):
        raise ValueError("URL cannot contain whitespace.")

    return candidate


def is_valid_url(value: str) -> bool:
    try:
        normalize_url(value)
    except ValueError:
        return False

    return True

import re
from typing import Dict, List

from services.file_type_service import is_text_file


URL_RE = re.compile(r"\bhttps?://[^\s<>'\"()]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\b",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")


def _unique(values: List[str]) -> List[str]:
    seen = set()
    output = []

    for value in values:
        normalized = value.strip().rstrip(".,;:)]}")
        key = normalized.lower()

        if normalized and key not in seen:
            seen.add(key)
            output.append(normalized)

    return output


def empty_iocs() -> Dict[str, List[str]]:
    return {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "hashes": [],
    }


def extract_iocs(file_bytes: bytes, file_type: dict) -> Dict[str, List[str]]:
    """
    Extract lightweight indicators from text files using regex only.

    Binary and non-text files intentionally return empty IOC arrays.
    """

    if not is_text_file(file_type):
        return empty_iocs()

    try:
        text = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return empty_iocs()

    urls = _unique(URL_RE.findall(text))
    emails = _unique(EMAIL_RE.findall(text))
    ips = _unique(IPV4_RE.findall(text))
    hashes = _unique(HASH_RE.findall(text))

    domains = _unique(DOMAIN_RE.findall(text))
    url_hosts = []
    for url in urls:
        match = re.match(r"^https?://([^/:?#]+)", url, re.IGNORECASE)
        if match:
            url_hosts.append(match.group(1))

    domains = _unique(domains + url_hosts)

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "hashes": hashes,
    }


def build_text_preview(file_bytes: bytes, file_type: dict, max_lines: int = 20) -> list[str]:
    if not is_text_file(file_type):
        return []

    text = file_bytes.decode("utf-8", errors="ignore")
    return text.splitlines()[:max_lines]

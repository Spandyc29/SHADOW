import hashlib
import re
from typing import Dict, Tuple


def generate_hashes(file_bytes: bytes) -> Dict[str, str]:
    """
    Generate MD5, SHA1 and SHA256 hashes.
    """

    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def validate_hash(hash_value: str) -> Tuple[bool, str]:
    """
    Validate a hash and identify its type.

    Returns:
        (True, "md5")
        (True, "sha1")
        (True, "sha256")

    or

        (False, "")
    """

    if not isinstance(hash_value, str):
        return False, ""

    hash_value = hash_value.strip().lower()

    if re.fullmatch(r"[a-f0-9]{32}", hash_value):
        return True, "md5"

    if re.fullmatch(r"[a-f0-9]{40}", hash_value):
        return True, "sha1"

    if re.fullmatch(r"[a-f0-9]{64}", hash_value):
        return True, "sha256"

    return False, ""
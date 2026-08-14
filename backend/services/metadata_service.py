import os
import mimetypes
from pathlib import Path
from datetime import datetime


def extract_metadata(file_path: str) -> dict:
    file = Path(file_path)

    mime_type, _ = mimetypes.guess_type(file_path)

    metadata = {
        "filename": file.name,
        "extension": file.suffix.lower(),
        "mime_type": mime_type or "Unknown",
        "file_size": os.path.getsize(file_path),
        "upload_time": datetime.utcnow().isoformat(),

        # Future fields
        "is_executable": False,
        "is_pe_file": False,
        "entropy": None,
        "architecture": None,
        "compile_timestamp": None,
        "is_signed": None,
    }

    return metadata
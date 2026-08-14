import mimetypes
from pathlib import Path


WINDOWS_EXTENSIONS = {".exe", ".dll", ".sys", ".msi"}
ANDROID_EXTENSIONS = {".apk"}
LINUX_EXTENSIONS = {".elf", ".so", ".run", ".sh"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".js", ".py", ".vbs"}
DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".csv",
    ".xml",
    ".json",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}
GENERIC_EXTENSIONS = {".bin"}

TEXT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".py",
    ".vbs",
    ".sh",
    ".txt",
    ".csv",
    ".xml",
    ".json",
}

SUPPORTED_EXTENSIONS = (
    WINDOWS_EXTENSIONS
    | ANDROID_EXTENSIONS
    | LINUX_EXTENSIONS
    | SCRIPT_EXTENSIONS
    | DOCUMENT_EXTENSIONS
    | ARCHIVE_EXTENSIONS
    | GENERIC_EXTENSIONS
)

EXTENSION_CATEGORIES = {
    **{extension: "windows" for extension in WINDOWS_EXTENSIONS},
    **{extension: "android" for extension in ANDROID_EXTENSIONS},
    **{extension: "linux" for extension in LINUX_EXTENSIONS},
    **{extension: "script" for extension in SCRIPT_EXTENSIONS},
    **{extension: "document" for extension in DOCUMENT_EXTENSIONS},
    **{extension: "archive" for extension in ARCHIVE_EXTENSIONS},
    **{extension: "generic" for extension in GENERIC_EXTENSIONS},
}

EXTENSION_TYPES = {
    ".exe": "Windows Executable",
    ".dll": "Windows Dynamic Link Library",
    ".sys": "Windows Driver",
    ".msi": "Windows Installer",
    ".apk": "Android Package",
    ".elf": "Linux ELF Binary",
    ".so": "Linux Shared Object",
    ".run": "Linux Installer",
    ".sh": "Shell Script",
    ".bat": "Batch Script",
    ".cmd": "Command Script",
    ".ps1": "PowerShell Script",
    ".js": "JavaScript",
    ".py": "Python Script",
    ".vbs": "VBScript",
    ".pdf": "PDF Document",
    ".doc": "Word Document",
    ".docx": "Word Document",
    ".xls": "Excel Spreadsheet",
    ".xlsx": "Excel Spreadsheet",
    ".ppt": "PowerPoint Presentation",
    ".pptx": "PowerPoint Presentation",
    ".txt": "Text File",
    ".csv": "CSV File",
    ".xml": "XML File",
    ".json": "JSON File",
    ".zip": "ZIP Archive",
    ".rar": "RAR Archive",
    ".7z": "7-Zip Archive",
    ".tar": "TAR Archive",
    ".gz": "Gzip Archive",
    ".iso": "ISO Disk Image",
    ".bin": "Binary File",
}


def detect_file_type(file_path: str, filename: str | None = None) -> dict:
    """
    Detect lightweight file type details from filename, extension, and MIME.

    This intentionally avoids deep file parsing.
    """

    source_name = filename or Path(file_path).name
    extension = Path(source_name).suffix.lower()
    mime_type, _ = mimetypes.guess_type(source_name)

    return {
        "type": EXTENSION_TYPES.get(extension, "Unknown File"),
        "category": EXTENSION_CATEGORIES.get(extension, "unknown"),
        "mime": mime_type or "application/octet-stream",
        "extension": extension,
    }


def is_text_file(file_type: dict) -> bool:
    extension = file_type.get("extension")
    mime_type = str(file_type.get("mime") or "").lower()

    return extension in TEXT_EXTENSIONS or mime_type.startswith("text/")

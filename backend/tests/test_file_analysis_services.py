from services.file_type_service import detect_file_type
from services.ioc_extractor import build_text_preview, extract_iocs


def test_detect_file_type_uses_extension_and_mime():
    result = detect_file_type("sample.exe")

    assert result["type"] == "Windows Executable"
    assert result["category"] == "windows"
    assert result["extension"] == ".exe"
    assert result["mime"] in {
        "application/x-msdos-program",
        "application/x-msdownload",
    }


def test_extract_iocs_from_text_file():
    file_type = detect_file_type("sample.txt")
    content = (
        b"Visit https://example.com/path and email test@example.org\n"
        b"IP 192.168.1.10 hash "
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    result = extract_iocs(content, file_type)

    assert result["urls"] == ["https://example.com/path"]
    assert "example.com" in result["domains"]
    assert "example.org" in result["domains"]
    assert result["ips"] == ["192.168.1.10"]
    assert result["emails"] == ["test@example.org"]
    assert result["hashes"] == [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ]


def test_binary_ioc_extraction_returns_empty_arrays():
    file_type = detect_file_type("sample.bin")

    assert extract_iocs(b"https://example.com", file_type) == {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "hashes": [],
    }


def test_preview_is_first_twenty_lines_for_text_only():
    file_type = detect_file_type("sample.py")
    content = "\n".join(f"line {index}" for index in range(25)).encode()

    preview = build_text_preview(content, file_type)

    assert len(preview) == 20
    assert preview[0] == "line 0"
    assert preview[-1] == "line 19"
    assert build_text_preview(content, detect_file_type("sample.exe")) == []

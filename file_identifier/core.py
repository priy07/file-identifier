"""
File Type Identifier using Magic Numbers
Reads file headers (magic bytes) to identify file types - no extensions needed.
"""

import struct
from pathlib import Path

MAGIC_SIGNATURES = [
    # Images
    (b'\xff\xd8\xff',                       "JPEG Image",           ".jpg"),
    (b'\x89PNG\r\n\x1a\n',                  "PNG Image",            ".png"),
    (b'GIF87a',                             "GIF Image (87a)",      ".gif"),
    (b'GIF89a',                             "GIF Image (89a)",      ".gif"),
    (b'BM',                                 "BMP Image",            ".bmp"),
    (b'RIFF',                               "RIFF (WAV/AVI/WebP)",  ".riff"),
    (b'\x00\x00\x01\x00',                   "ICO Icon",             ".ico"),
    (b'\x49\x49\x2a\x00',                   "TIFF (little-endian)", ".tif"),
    (b'\x4d\x4d\x00\x2a',                   "TIFF (big-endian)",    ".tif"),

    # Documents
    (b'%PDF',                               "PDF Document",         ".pdf"),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  "MS Office (old)",      ".doc/.xls/.ppt"),
    (b'PK\x03\x04',                         "ZIP / Office Open XML",".zip/.docx/.xlsx"),

    # Audio / Video
    (b'ID3',                                "MP3 Audio (ID3 tag)",  ".mp3"),
    (b'\xff\xfb',                           "MP3 Audio",            ".mp3"),
    (b'\xff\xf3',                           "MP3 Audio",            ".mp3"),
    (b'fLaC',                               "FLAC Audio",           ".flac"),
    (b'OggS',                               "OGG Container",        ".ogg"),
    (b'\x1aE\xdf\xa3',                      "Matroska/WebM",        ".mkv/.webm"),
    (b'\x00\x00\x00\x18ftypmp4',            "MP4 Video",            ".mp4"),
    (b'\x00\x00\x00\x20ftyp',              "MP4 Video",            ".mp4"),

    # Archives
    (b'\x1f\x8b',                           "GZIP Archive",         ".gz"),
    (b'BZh',                                "BZIP2 Archive",        ".bz2"),
    (b'\xfd7zXZ\x00',                       "XZ Archive",           ".xz"),
    (b'7z\xbc\xaf\x27\x1c',                "7-Zip Archive",        ".7z"),
    (b'Rar!\x1a\x07\x00',                  "RAR Archive (v4)",     ".rar"),
    (b'Rar!\x1a\x07\x01\x00',             "RAR Archive (v5)",     ".rar"),

    # Executables / Binary
    (b'MZ',                                 "Windows Executable",   ".exe/.dll"),
    (b'\x7fELF',                            "ELF Executable (Linux)",".elf"),
    (b'\xca\xfe\xba\xbe',                   "Java Class / Mach-O",  ".class"),
    (b'\xfe\xed\xfa\xce',                   "Mach-O 32-bit",        ".macho"),
    (b'\xfe\xed\xfa\xcf',                   "Mach-O 64-bit",        ".macho"),

    # Text / Code (heuristic, checked last)
    (b'#!/',                                "Shell Script",         ".sh"),
    (b'<?xml',                              "XML Document",         ".xml"),
    (b'<?php',                              "PHP Script",           ".php"),
    (b'<html',                              "HTML Document",        ".html"),
    (b'<HTML',                              "HTML Document",        ".html"),
    (b'{\n',                                "JSON (likely)",        ".json"),
    (b'{\r\n',                              "JSON (likely)",        ".json"),
]

MAX_HEADER = 32  # bytes to read from the file


def read_header(filepath: str) -> bytes:
    """Read the first MAX_HEADER bytes of a file."""
    with open(filepath, 'rb') as f:
        return f.read(MAX_HEADER)


def identify_file(filepath: str) -> dict:
    """
    Identify a file's type by reading its magic bytes.

    Returns a dict with:
        path        - original filepath
        hex_header  - hex dump of the first bytes
        file_type   - human-readable type name
        extension   - likely extension(s)
        matched_sig - the raw signature that matched (hex)
        confidence  - 'high' or 'low'
    """
    path = Path(filepath)
    result = {
        "path":        str(path),
        "size_bytes":  path.stat().st_size if path.exists() else 0,
        "file_type":   "Unknown",
        "extension":   "?",
        "hex_header":  "",
        "matched_sig": "",
        "confidence":  "low",
    }

    if not path.exists():
        result["file_type"] = "File not found"
        return result

    if path.stat().st_size == 0:
        result["file_type"] = "Empty file"
        return result

    header = read_header(filepath)
    result["hex_header"] = " ".join(f"{b:02X}" for b in header)

    for sig, name, ext in MAGIC_SIGNATURES:
        if header[:len(sig)] == sig:
            result["file_type"]   = name
            result["extension"]   = ext
            result["matched_sig"] = sig.hex(" ")
            result["confidence"]  = "high" if len(sig) >= 4 else "medium"
            return result

    # Fallback: try to detect plain text (reject if null bytes present)
    try:
        decoded = header.decode('utf-8')
        if '\x00' in decoded:
            raise UnicodeDecodeError('utf-8', b'', 0, 1, 'null byte')
        result["file_type"]  = "Plain Text (UTF-8)"
        result["extension"]  = ".txt"
        result["confidence"] = "medium"
    except UnicodeDecodeError:
        result["file_type"]  = "Unknown Binary"
        result["extension"]  = ".bin"
        result["confidence"] = "low"

    return result


def identify_many(filepaths: list[str]) -> list[dict]:
    """Identify multiple files at once."""
    return [identify_file(fp) for fp in filepaths]


def print_report(result: dict) -> None:
    """Pretty-print a single file identification result."""
    print(f"\n{'='*55}")
    print(f"  File    : {result['path']}")
    print(f"  Type    : {result['file_type']}")
    print(f"  Ext     : {result['extension']}")
    print(f"  Size    : {result['size_bytes']:,} bytes")
    print(f"  Confidence : {result['confidence']}")
    print(f"  Header  : {result['hex_header']}")
    if result['matched_sig']:
        print(f"  Matched : {result['matched_sig']}")
    print(f"{'='*55}")

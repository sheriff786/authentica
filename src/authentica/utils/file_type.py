"""
File type detection via magic bytes — inspired by ExifTool's approach
of never trusting file extensions, always reading the actual bytes.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path


class FileType(str, Enum):
    JPEG = "image/jpeg"
    PNG = "image/png"
    WEBP = "image/webp"
    TIFF = "image/tiff"
    GIF = "image/gif"
    HEIC = "image/heic"
    PDF = "application/pdf"
    MP4 = "video/mp4"
    MOV = "video/quicktime"
    UNKNOWN = "application/octet-stream"


# Magic byte signatures: (offset, bytes_to_match)
_MAGIC: list[tuple[int, bytes, FileType]] = [
    (0, b"\xff\xd8\xff",           FileType.JPEG),
    (0, b"\x89PNG\r\n\x1a\n",     FileType.PNG),
    (8, b"WEBP",                   FileType.WEBP),
    (0, b"II\x2a\x00",            FileType.TIFF),   # little-endian TIFF
    (0, b"MM\x00\x2a",            FileType.TIFF),   # big-endian TIFF
    (0, b"GIF87a",                 FileType.GIF),
    (0, b"GIF89a",                 FileType.GIF),
    (0, b"%PDF-",                  FileType.PDF),
    (4, b"ftyp",                   FileType.MP4),    # MP4/HEIC share ftyp box
    (0, b"\x00\x00\x00\x14ftypqt", FileType.MOV),
]

# HEIC brand codes inside the ftyp box
_HEIC_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}


def detect_file_type(path: Path) -> FileType:
    """
    Detect file type from magic bytes, not extension.

    Reads only the first 32 bytes — fast and extension-agnostic,
    mirroring ExifTool's philosophy of trusting content over naming.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(32)
    except OSError:
        return FileType.UNKNOWN

    for offset, magic, file_type in _MAGIC:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            # Disambiguate MP4 vs HEIC by reading brand codes
            if file_type == FileType.MP4:
                brand = header[8:12]
                if brand in _HEIC_BRANDS:
                    return FileType.HEIC
            return file_type

    return FileType.UNKNOWN

"""
Authentica — AI content authenticity detection library.

Quick start:
    from authentica import scan
    result = scan("photo.jpg")
    print(result.summary())

Metadata reading (like ExifTool):
    from authentica.metadata import MetadataReader
    meta = MetadataReader().read("photo.jpg")
    print(meta.exif["Make"], meta.gps.coord_format("dms"))

Batch scanning:
    from authentica.scanner import BatchScanner
    scanner = BatchScanner(extensions={".jpg"}, recurse=True)
    for path in scanner.walk("/photos"):
        print(path)

Metadata diff:
    from authentica.metadata.diff import diff_metadata
    d = diff_metadata("original.jpg", "edited.jpg")
    print(d.summary())
"""

from authentica.core import scan, ScanResult
from authentica.c2pa.reader import C2PAReader
from authentica.watermark.detector import WatermarkDetector
from authentica.forensics.analyzer import ForensicsAnalyzer
from authentica.metadata.reader import MetadataReader
from authentica.metadata.diff import diff_metadata
from authentica.scanner.batch import BatchScanner

__version__ = "0.2.2"
__author__ = "Authentica contributors"
__license__ = "MIT"

__all__ = [
    "scan", "ScanResult",
    "C2PAReader",
    "WatermarkDetector",
    "ForensicsAnalyzer",
    "MetadataReader",
    "diff_metadata",
    "BatchScanner",
    "__version__",
]

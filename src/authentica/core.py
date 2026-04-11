"""
Core scan interface — runs all analyzers and aggregates results.
This is the main entry point: `authentica.scan("file.jpg")`
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from authentica.c2pa.reader import C2PAReader, C2PAResult
from authentica.watermark.detector import WatermarkDetector, WatermarkResult
from authentica.forensics.analyzer import ForensicsAnalyzer, ForensicsResult
from authentica.utils.file_type import detect_file_type, FileType


@dataclass
class ScanResult:
    """
    Aggregated result from all analyzers run on a single file.

    Attributes:
        file_path:    Path to the scanned file.
        file_type:    Detected MIME-like file type string.
        scan_time_s:  Wall-clock seconds the scan took.
        c2pa:         C2PA manifest read result (None if unsupported).
        watermark:    Passive watermark detection result.
        forensics:    Image forensics result.
        errors:       Any non-fatal errors encountered per analyzer.
    """

    file_path: Path
    file_type: str
    scan_time_s: float
    c2pa: Optional[C2PAResult] = None
    watermark: Optional[WatermarkResult] = None
    forensics: Optional[ForensicsResult] = None
    errors: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    #  Convenience helpers                                                 #
    # ------------------------------------------------------------------ #

    @property
    def has_c2pa(self) -> bool:
        """True if a valid C2PA manifest was found."""
        return self.c2pa is not None and self.c2pa.manifest_found

    @property
    def has_watermark(self) -> bool:
        """True if a passive invisible watermark signal was detected."""
        return self.watermark is not None and self.watermark.detected

    @property
    def trust_score(self) -> float:
        """
        Heuristic 0-100 authenticity score.

        100 = strong provenance signals (C2PA valid + no anomalies).
        0   = no provenance, strong forensic anomalies detected.
        """
        score = 50.0  # default: unknown

        if self.c2pa:
            if self.c2pa.manifest_found and self.c2pa.signature_valid:
                score += 25.0
            elif self.c2pa.manifest_found and not self.c2pa.signature_valid:
                score -= 20.0

        if self.forensics:
            score -= self.forensics.anomaly_score * 40.0

        if self.watermark and self.watermark.detected:
            score += 10.0

        return max(0.0, min(100.0, score))

    def summary(self) -> str:
        """Return a human-readable one-line summary."""
        parts = [f"[{self.file_path.name}]"]
        parts.append(f"type={self.file_type}")
        parts.append(f"trust={self.trust_score:.0f}/100")
        parts.append(f"c2pa={'✓' if self.has_c2pa else '✗'}")
        parts.append(f"watermark={'✓' if self.has_watermark else '✗'}")
        if self.errors:
            parts.append(f"errors={list(self.errors.keys())}")
        return "  ".join(parts)

    def to_dict(self) -> dict:
        """Serialise result to a plain dictionary (JSON-safe)."""
        return {
            "file": str(self.file_path),
            "file_type": self.file_type,
            "scan_time_s": round(self.scan_time_s, 3),
            "trust_score": round(self.trust_score, 1),
            "c2pa": self.c2pa.to_dict() if self.c2pa else None,
            "watermark": self.watermark.to_dict() if self.watermark else None,
            "forensics": self.forensics.to_dict() if self.forensics else None,
            "errors": self.errors,
        }


def scan(
    path: str | Path,
    *,
    run_c2pa: bool = True,
    run_watermark: bool = True,
    run_forensics: bool = True,
) -> ScanResult:
    """
    Scan a file for AI content authenticity signals.

    This is the main high-level API. It auto-detects the file type,
    runs the requested analyzers, and returns a unified ScanResult.

    Args:
        path:           Path to image, PDF, or video file.
        run_c2pa:       Whether to check for C2PA content credentials.
        run_watermark:  Whether to run passive watermark detection.
        run_forensics:  Whether to run image forensics analysis.

    Returns:
        ScanResult with all findings aggregated.

    Example:
        >>> result = scan("photo.jpg")
        >>> print(result.summary())
        >>> if result.has_c2pa:
        ...     print(result.c2pa.assertions)
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    t0 = time.perf_counter()
    file_type = detect_file_type(path)
    errors: dict[str, str] = {}

    # --- C2PA ---
    c2pa_result: Optional[C2PAResult] = None
    if run_c2pa:
        try:
            c2pa_result = C2PAReader().read(path)
        except Exception as exc:
            errors["c2pa"] = str(exc)

    # --- Watermark (images only) ---
    wm_result: Optional[WatermarkResult] = None
    if run_watermark and file_type in (FileType.JPEG, FileType.PNG, FileType.WEBP, FileType.TIFF):
        try:
            wm_result = WatermarkDetector().detect(path)
        except Exception as exc:
            errors["watermark"] = str(exc)

    # --- Forensics (images only) ---
    forensics_result: Optional[ForensicsResult] = None
    if run_forensics and file_type in (FileType.JPEG, FileType.PNG, FileType.WEBP, FileType.TIFF):
        try:
            forensics_result = ForensicsAnalyzer().analyze(path)
        except Exception as exc:
            errors["forensics"] = str(exc)

    elapsed = time.perf_counter() - t0

    return ScanResult(
        file_path=path,
        file_type=file_type.value,
        scan_time_s=elapsed,
        c2pa=c2pa_result,
        watermark=wm_result,
        forensics=forensics_result,
        errors=errors,
    )

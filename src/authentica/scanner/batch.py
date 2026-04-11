"""
Batch file scanner — recursive directory processing with filtering.

Mirrors ExifTool's:
  exiftool -r -ext jpg DIR     (recurse, filter by extension)
  exiftool -progress DIR       (show progress)
  exiftool -csv DIR > out.csv  (batch CSV export)

Cross-platform: uses pathlib.Path throughout, works on
Windows, macOS, and Linux without path separator issues.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generator, Optional


# Extensions to scan by default (mirrors ExifTool's supported image types)
DEFAULT_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".gif", ".bmp", ".avif",
    ".mp4", ".mov", ".m4v", ".m4a", ".3gp",
    ".mp3", ".flac", ".wav", ".ogg", ".aac",
    ".pdf", ".xmp", ".dng", ".cr2", ".cr3",
    ".nef", ".arw", ".raf", ".orf", ".rw2",
}


@dataclass
class ScanStats:
    total_files: int = 0
    processed: int = 0
    errors: int = 0
    skipped: int = 0
    elapsed_s: float = 0.0

    def summary(self) -> str:
        rate = self.processed / self.elapsed_s if self.elapsed_s else 0
        return (
            f"{self.processed}/{self.total_files} files  "
            f"{self.errors} errors  "
            f"{rate:.1f} files/s  "
            f"{self.elapsed_s:.1f}s"
        )


class BatchScanner:
    """
    Recursively scan directories and process files.

    Mirrors ExifTool's directory-scanning behavior:
    - Recurse into subdirectories (-r)
    - Filter by extension (-ext)
    - Skip hidden files/dirs (like ExifTool's default)
    - Show progress (-progress)
    - Export CSV / JSON

    Usage:
        scanner = BatchScanner(extensions={".jpg", ".png"}, recurse=True)
        for path in scanner.walk("/photos"):
            result = scan(path)
            print(result.summary())
    """

    def __init__(
        self,
        extensions: Optional[set[str]] = None,
        recurse: bool = True,
        skip_hidden: bool = True,
        ignore_dirs: Optional[set[str]] = None,
        progress: bool = False,
    ):
        self.extensions = {e.lower() for e in (extensions or DEFAULT_EXTENSIONS)}
        self.recurse = recurse
        self.skip_hidden = skip_hidden
        self.ignore_dirs = ignore_dirs or {"__pycache__", ".git", "node_modules", ".Trash"}
        self.progress = progress

    def walk(self, root: str | Path) -> Generator[Path, None, None]:
        """
        Yield file paths matching the configured extensions.
        Cross-platform — uses pathlib.Path, no os.sep needed.
        """
        root = Path(root)

        if root.is_file():
            if self._accept(root):
                yield root
            return

        if not root.is_dir():
            return

        iterator = root.rglob("*") if self.recurse else root.iterdir()

        for path in iterator:
            if not path.is_file():
                continue
            # Skip hidden files (start with ".")
            if self.skip_hidden and path.name.startswith("."):
                continue
            # Skip ignored directories anywhere in the path
            if any(part in self.ignore_dirs for part in path.parts):
                continue
            if self._accept(path):
                yield path

    def _accept(self, path: Path) -> bool:
        """Return True if path should be processed."""
        return path.suffix.lower() in self.extensions

    def scan_all(
        self,
        root: str | Path,
        processor: Callable[[Path], dict],
    ) -> tuple[list[dict], ScanStats]:
        """
        Scan all matching files, apply processor, collect results.

        Args:
            root:       Directory or file to scan.
            processor:  Callable(Path) -> dict. Called for each file.

        Returns:
            (results list, ScanStats)
        """
        paths = list(self.walk(root))
        stats = ScanStats(total_files=len(paths))
        results: list[dict] = []
        t0 = time.perf_counter()

        for i, path in enumerate(paths):
            if self.progress:
                pct = (i + 1) / max(len(paths), 1) * 100
                sys.stderr.write(f"\r[{pct:5.1f}%] {path.name[:40]:<40}")
                sys.stderr.flush()
            try:
                result = processor(path)
                result.setdefault("SourceFile", str(path))
                results.append(result)
                stats.processed += 1
            except Exception as exc:
                stats.errors += 1
                results.append({
                    "SourceFile": str(path),
                    "Error": str(exc),
                })

        if self.progress:
            sys.stderr.write("\n")

        stats.elapsed_s = time.perf_counter() - t0
        return results, stats


def results_to_csv(results: list[dict], output: Optional[str | Path] = None) -> str:
    """
    Export scan results to CSV — mirrors `exiftool -csv DIR`.
    If output is None, returns CSV as string. Otherwise writes to file.
    """
    if not results:
        return ""

    # Gather all keys across all results (union)
    all_keys: list[str] = ["SourceFile"]
    seen: set[str] = {"SourceFile"}
    for r in results:
        for k in r:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=all_keys, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for r in results:
        writer.writerow({k: r.get(k, "") for k in all_keys})

    csv_str = buf.getvalue()

    if output:
        Path(output).write_text(csv_str, encoding="utf-8")

    return csv_str


def results_to_json(results: list[dict], output: Optional[str | Path] = None) -> str:
    """
    Export scan results to JSON — mirrors `exiftool -json DIR`.
    """
    def _safe(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, Path):
            return str(obj)
        return str(obj)

    json_str = json.dumps(results, indent=2, default=_safe)

    if output:
        Path(output).write_text(json_str, encoding="utf-8")

    return json_str

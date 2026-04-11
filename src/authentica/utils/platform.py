"""
Cross-platform support layer.

ExifTool solves Windows portability by bundling perl.exe + DLLs.
We solve it the Python way: detect the OS at runtime and adjust
path separators, terminal encoding, and subprocess calls accordingly.

Works identically on: Linux, macOS, Windows (CMD, PowerShell, WSL).
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


# ── OS detection ──────────────────────────────────────────────────────────────

SYSTEM = platform.system()          # "Linux" | "Darwin" | "Windows"
IS_WINDOWS = SYSTEM == "Windows"
IS_MACOS = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"


def terminal_encoding() -> str:
    """Return the best output encoding for the current terminal."""
    if IS_WINDOWS:
        # CMD defaults to cp1252; PowerShell to utf-8 on modern Windows
        return os.environ.get("PYTHONIOENCODING", "utf-8")
    return sys.stdout.encoding or "utf-8"


def normalize_path(path: str | Path) -> Path:
    """
    Normalize a path for the current OS.
    On Windows, converts forward slashes and expands ~ correctly.
    ExifTool does the same via Perl's File::Spec.
    """
    return Path(path).expanduser().resolve()


def safe_filename(name: str) -> str:
    """
    Strip characters that are illegal in filenames on any OS.

    Always strips the full Windows-illegal set: backslash, /, :, *, ?, ", <, >, |
    so that files generated on Linux/macOS are also safe to copy to Windows.
    This mirrors ExifTool's cross-platform filename-cleaning behaviour.
    """
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name


def platform_info() -> dict:
    """Return a structured dict of platform details (like exiftool -ver -v)."""
    return {
        "os": SYSTEM,
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
        "python_path": sys.executable,
        "is_64bit": sys.maxsize > 2**32,
    }

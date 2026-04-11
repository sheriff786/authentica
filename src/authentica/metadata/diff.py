"""
Metadata diff — compare metadata between two files.

Mirrors ExifTool's  `exiftool -diff FILE1 FILE2` feature.
Shows added, removed, and changed tags between two files.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authentica.metadata.reader import MetadataReader, MetadataResult


@dataclass
class DiffEntry:
    tag: str
    value_a: Any
    value_b: Any

    @property
    def status(self) -> str:
        if self.value_a is None:
            return "added"
        if self.value_b is None:
            return "removed"
        return "changed"

    def to_dict(self) -> dict:
        return {
            "tag": self.tag,
            "status": self.status,
            "from": self.value_a,
            "to": self.value_b,
        }


@dataclass
class MetadataDiff:
    file_a: Path
    file_b: Path
    entries: list[DiffEntry]

    @property
    def added(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.status == "added"]

    @property
    def removed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.status == "removed"]

    @property
    def changed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.status == "changed"]

    def to_dict(self) -> dict:
        return {
            "file_a": str(self.file_a),
            "file_b": str(self.file_b),
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "entries": [e.to_dict() for e in self.entries],
        }

    def summary(self) -> str:
        return (
            f"[{self.file_a.name} ↔ {self.file_b.name}]  "
            f"+{len(self.added)} added  "
            f"-{len(self.removed)} removed  "
            f"~{len(self.changed)} changed"
        )


def diff_metadata(path_a: str | Path, path_b: str | Path) -> MetadataDiff:
    """
    Compare metadata between two files and return structured diff.

    Usage:
        diff = diff_metadata("original.jpg", "edited.jpg")
        print(diff.summary())
        for entry in diff.changed:
            print(f"  {entry.tag}: {entry.value_a!r} → {entry.value_b!r}")
    """
    reader = MetadataReader(compute_hashes=True)
    meta_a = reader.read(path_a)
    meta_b = reader.read(path_b)

    tags_a = meta_a.all_tags
    tags_b = meta_b.all_tags

    all_keys = sorted(set(tags_a) | set(tags_b))
    entries: list[DiffEntry] = []

    for key in all_keys:
        va = tags_a.get(key)
        vb = tags_b.get(key)
        if va != vb:
            entries.append(DiffEntry(tag=key, value_a=va, value_b=vb))

    return MetadataDiff(
        file_a=Path(path_a),
        file_b=Path(path_b),
        entries=entries,
    )

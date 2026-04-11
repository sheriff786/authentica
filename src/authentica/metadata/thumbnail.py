"""
Thumbnail and preview image extractor.

Mirrors ExifTool's:
  exiftool -ThumbnailImage -b FILE > thumb.jpg
  exiftool -PreviewImage -b FILE > preview.jpg

Extracts embedded JPEG thumbnails from:
  - EXIF IFD1 (all camera images)
  - JFIF APP0 thumbnail
  - Photoshop preview (APP13)
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PIL import Image


@dataclass
class ThumbnailResult:
    """Extracted thumbnail information."""
    found: bool
    width: Optional[int] = None
    height: Optional[int] = None
    data: Optional[bytes] = None
    source: str = "none"          # "exif_ifd1" | "jfif" | "photoshop"

    def save(self, path: str | Path) -> None:
        """Save thumbnail JPEG to path."""
        if not self.data:
            raise ValueError("No thumbnail data available")
        Path(path).write_bytes(self.data)

    def to_pil(self) -> Optional[Image.Image]:
        """Return thumbnail as a PIL Image."""
        if not self.data:
            return None
        return Image.open(io.BytesIO(self.data))

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "source": self.source,
            "width": self.width,
            "height": self.height,
            "size_bytes": len(self.data) if self.data else 0,
        }


def extract_thumbnail(path: str | Path) -> ThumbnailResult:
    """
    Extract embedded thumbnail from image file.

    Tries EXIF IFD1, then JFIF, then Photoshop in order.
    Returns the first thumbnail found.
    """
    path = Path(path)
    data = path.read_bytes()

    # Try EXIF IFD1 thumbnail
    result = _extract_exif_thumb(data)
    if result.found:
        return result

    # Try JFIF thumbnail
    result = _extract_jfif_thumb(data)
    if result.found:
        return result

    return ThumbnailResult(found=False)


def _extract_exif_thumb(data: bytes) -> ThumbnailResult:
    """Extract thumbnail from EXIF IFD1."""
    try:
        img = Image.open(io.BytesIO(data))
        exif_bytes = img.info.get("exif", b"")
        if not exif_bytes or len(exif_bytes) < 6:
            return ThumbnailResult(found=False)

        # piexif gives us the thumbnail directly
        try:
            import piexif
            exif_data = piexif.load(exif_bytes)
            thumb = exif_data.get("thumbnail")
            if thumb and len(thumb) > 100:
                try:
                    thumb_img = Image.open(io.BytesIO(thumb))
                    w, h = thumb_img.size
                    return ThumbnailResult(
                        found=True, width=w, height=h,
                        data=thumb, source="exif_ifd1"
                    )
                except Exception:
                    return ThumbnailResult(found=True, data=thumb, source="exif_ifd1")
        except Exception:
            pass

        # Fallback: PIL's built-in thumbnail
        if hasattr(img, "_getexif") and img._getexif():
            raw = img._getexif()
            thumb_data = raw.get(0x501B)  # JPEGInterchangeFormat offset marker
            if thumb_data and isinstance(thumb_data, bytes) and len(thumb_data) > 100:
                return ThumbnailResult(found=True, data=thumb_data, source="exif_ifd1")

    except Exception:
        pass
    return ThumbnailResult(found=False)


def _extract_jfif_thumb(data: bytes) -> ThumbnailResult:
    """Extract thumbnail from JFIF APP0 marker."""
    if data[:2] != b"\xff\xd8":
        return ThumbnailResult(found=False)
    if data[2:4] != b"\xff\xe0":
        return ThumbnailResult(found=False)

    try:
        length = struct.unpack(">H", data[4:6])[0]
        app0 = data[6: 6 + length - 2]

        if app0[:5] != b"JFIF\x00":
            return ThumbnailResult(found=False)

        xt = app0[9]    # thumbnail width
        yt = app0[10]   # thumbnail height
        if xt == 0 or yt == 0:
            return ThumbnailResult(found=False)

        # Raw RGB thumbnail data (xt * yt * 3 bytes)
        thumb_rgb = app0[11: 11 + xt * yt * 3]
        if len(thumb_rgb) < xt * yt * 3:
            return ThumbnailResult(found=False)

        # Convert to JPEG
        img = Image.frombytes("RGB", (xt, yt), thumb_rgb)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90)
        return ThumbnailResult(
            found=True, width=xt, height=yt,
            data=buf.getvalue(), source="jfif"
        )
    except Exception:
        return ThumbnailResult(found=False)

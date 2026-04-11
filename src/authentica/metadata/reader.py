"""
Full metadata reader — EXIF, IPTC, XMP, GPS, ICC, Photoshop, ID3, QuickTime.

This is the Python equivalent of ExifTool's Image::ExifTool module.
It reads structured metadata from images, audio, and video files
without any external binary dependency — pure Python, any OS.

Supported metadata namespaces:
  EXIF     — camera settings, GPS, timestamps, thumbnail
  IPTC     — creator, copyright, keywords, caption
  XMP      — Dublin Core, photoshop, rights, camera raw
  GPS      — latitude, longitude, altitude, speed, direction
  ICC      — color profile name and intent
  JFIF     — JPEG File Interchange Format header
  Photoshop — IRB blocks including IPTC-NAA
  ID3      — MP3 tags (title, artist, album, year, genre)
  QuickTime — MP4/MOV metadata atoms
"""

from __future__ import annotations

import hashlib
import io
import struct
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

try:
    import piexif
    _PIEXIF = True
except ImportError:
    _PIEXIF = False


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class GPSInfo:
    """Decoded GPS location from EXIF."""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    direction: Optional[float] = None
    speed: Optional[float] = None
    timestamp: Optional[str] = None
    raw: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "direction": self.direction,
            "speed": self.speed,
            "timestamp": self.timestamp,
        }

    def coord_format(self, fmt: str = "decimal") -> Optional[str]:
        """
        Format GPS coordinates. fmt = 'decimal' | 'dms' | 'exiftool'.
        Mirrors ExifTool's -c (coordFormat) option.
        """
        if self.latitude is None or self.longitude is None:
            return None
        if fmt == "decimal":
            return f"{self.latitude:.6f}, {self.longitude:.6f}"
        if fmt == "dms":
            return (
                f"{_deg_to_dms(abs(self.latitude))} {'N' if self.latitude >= 0 else 'S'}, "
                f"{_deg_to_dms(abs(self.longitude))} {'E' if self.longitude >= 0 else 'W'}"
            )
        # exiftool default: deg min sec
        return (
            f"{abs(self.latitude):.6f} deg, "
            f"{abs(self.longitude):.6f} deg"
        )


@dataclass
class MetadataResult:
    """
    Full structured metadata from a file.

    Mirrors the output of `exiftool -j -G -s FILE` — all tags,
    grouped by namespace, with GPS decoded and hashes computed.
    """
    file_path: Path
    file_size: int
    file_type: str
    mime_type: str

    # Tag groups (mirrors ExifTool's -g groupHeadings output)
    exif: dict[str, Any] = field(default_factory=dict)
    iptc: dict[str, Any] = field(default_factory=dict)
    xmp: dict[str, Any] = field(default_factory=dict)
    gps: Optional[GPSInfo] = None
    icc: dict[str, Any] = field(default_factory=dict)
    jfif: dict[str, Any] = field(default_factory=dict)
    photoshop: dict[str, Any] = field(default_factory=dict)
    id3: dict[str, Any] = field(default_factory=dict)
    quicktime: dict[str, Any] = field(default_factory=dict)
    composite: dict[str, Any] = field(default_factory=dict)

    # File integrity hashes
    md5: Optional[str] = None
    sha256: Optional[str] = None

    warnings: list[str] = field(default_factory=list)

    @property
    def all_tags(self) -> dict[str, Any]:
        """Flat dict of all tags across all groups (like exiftool -s FILE)."""
        combined: dict[str, Any] = {}
        for group_name in ("exif", "iptc", "xmp", "icc", "jfif",
                           "photoshop", "id3", "quicktime", "composite"):
            group = getattr(self, group_name, {})
            for k, v in group.items():
                combined[f"{group_name.upper()}:{k}"] = v
        if self.gps:
            for k, v in self.gps.to_dict().items():
                if v is not None:
                    combined[f"GPS:{k}"] = v
        return combined

    def to_dict(self, group: bool = True) -> dict:
        """Serialize to dict. group=True mirrors exiftool -g output."""
        base = {
            "SourceFile": str(self.file_path),
            "FileSize": self.file_size,
            "FileType": self.file_type,
            "MIMEType": self.mime_type,
            "MD5Sum": self.md5,
            "SHA256Sum": self.sha256,
            "Warnings": self.warnings,
        }
        if group:
            if self.exif:
                base["EXIF"] = self.exif
            if self.iptc:
                base["IPTC"] = self.iptc
            if self.xmp:
                base["XMP"] = self.xmp
            if self.gps:
                base["GPS"] = self.gps.to_dict()
            if self.icc:
                base["ICC_Profile"] = self.icc
            if self.jfif:
                base["JFIF"] = self.jfif
            if self.photoshop:
                base["Photoshop"] = self.photoshop
            if self.id3:
                base["ID3"] = self.id3
            if self.quicktime:
                base["QuickTime"] = self.quicktime
            if self.composite:
                base["Composite"] = self.composite
        else:
            base.update(self.all_tags)
        return base

    def save_thumbnail(self, output_path: str | Path) -> bool:
        """
        Extract and save the embedded JPEG thumbnail (EXIF IFD1).
        Returns True if thumbnail was found and saved.
        Mirrors exiftool -ThumbnailImage<= FILE extraction.
        """
        thumb = self.exif.get("ThumbnailJPEG")
        if not thumb:
            return False
        Path(output_path).write_bytes(thumb)
        return True


# ── Reader ────────────────────────────────────────────────────────────────────

class MetadataReader:
    """
    Read all metadata from a file — EXIF, IPTC, XMP, GPS, ID3, QuickTime.

    Pure Python, cross-platform. No ExifTool binary needed.

    Usage:
        reader = MetadataReader()
        meta = reader.read("photo.jpg")
        print(meta.exif["Make"], meta.exif["Model"])
        print(meta.gps.coord_format("dms"))
        print(meta.sha256)
    """

    def __init__(self, compute_hashes: bool = True):
        self.compute_hashes = compute_hashes

    def read(self, path: str | Path) -> MetadataResult:
        """Read all metadata from the file at path."""
        path = Path(path)
        data = path.read_bytes()
        stat = path.stat()

        result = MetadataResult(
            file_path=path,
            file_size=stat.st_size,
            file_type=path.suffix.lstrip(".").upper() or "UNKNOWN",
            mime_type=_guess_mime(data),
        )

        # Hashes (like exiftool's MD5Sum, SHA256Sum composite tags)
        if self.compute_hashes:
            result.md5 = hashlib.md5(data).hexdigest()
            result.sha256 = hashlib.sha256(data).hexdigest()

        suffix = path.suffix.lower()

        if suffix in (".jpg", ".jpeg", ".tif", ".tiff", ".webp", ".heic", ".heif"):
            self._read_image(path, data, result)
        elif suffix == ".png":
            self._read_png(data, result)
        elif suffix in (".mp3",):
            self._read_id3(data, result)
        elif suffix in (".mp4", ".mov", ".m4a", ".m4v", ".3gp"):
            self._read_quicktime(data, result)
        elif suffix == ".pdf":
            self._read_pdf(data, result)
        else:
            result.warnings.append(f"No metadata reader for {suffix}")

        # Composite tags (derived from primary tags, like ExifTool's Composite group)
        self._compute_composite(result)

        return result

    # ── Image (EXIF/IPTC/XMP/GPS/ICC) ────────────────────────────────────────

    def _read_image(self, path: Path, data: bytes, result: MetadataResult) -> None:
        """Read EXIF, GPS, IPTC, XMP from image via PIL + piexif."""
        try:
            img = Image.open(path)
        except Exception as exc:
            result.warnings.append(f"PIL open failed: {exc}")
            return

        # --- EXIF via PIL ---
        try:
            raw_exif = img._getexif()  # type: ignore[attr-defined]
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag_name = TAGS.get(tag_id, f"Tag_{tag_id:#06x}")
                    if tag_name == "GPSInfo" and isinstance(value, dict):
                        result.gps = _decode_gps(value)
                    elif tag_name == "MakerNote":
                        pass  # skip binary blobs
                    elif isinstance(value, bytes) and len(value) > 256:
                        pass  # skip large binary blobs
                    else:
                        result.exif[tag_name] = _clean_value(value)
        except Exception as exc:
            result.warnings.append(f"EXIF read error: {exc}")

        # --- Thumbnail via piexif ---
        if _PIEXIF:
            try:
                exif_bytes = img.info.get("exif", b"")
                if exif_bytes:
                    piexif_data = piexif.load(exif_bytes)
                    thumb = piexif_data.get("thumbnail")
                    if thumb:
                        result.exif["ThumbnailJPEG"] = thumb
            except Exception:
                pass

        # --- XMP (embedded as string in PIL info) ---
        xmp_str = img.info.get("XML:com.adobe.xmp") or img.info.get("xmp", "")
        if xmp_str:
            if isinstance(xmp_str, bytes):
                xmp_str = xmp_str.decode("utf-8", errors="replace")
            result.xmp = _parse_xmp(xmp_str)

        # --- IPTC via binary scan of JPEG APP13 ---
        if data[:2] == b"\xff\xd8":
            self._scan_jpeg_markers(data, result)

        # --- ICC Profile ---
        icc_bytes = img.info.get("icc_profile", b"")
        if icc_bytes:
            result.icc = _parse_icc(icc_bytes)

        # --- JFIF header ---
        jfif = img.info.get("jfif_version")
        if jfif:
            result.jfif = {
                "JFIFVersion": ".".join(str(v) for v in jfif),
                "ResolutionUnit": img.info.get("jfif_unit", 0),
                "XResolution": img.info.get("jfif_density", (0, 0))[0],
                "YResolution": img.info.get("jfif_density", (0, 0))[1],
            }

        # image-level composite info
        result.exif.setdefault("ImageWidth", img.width)
        result.exif.setdefault("ImageHeight", img.height)
        result.exif.setdefault("ColorSpace", img.mode)

    def _scan_jpeg_markers(self, data: bytes, result: MetadataResult) -> None:
        """Walk JPEG markers to extract APP13 (IPTC/Photoshop) and APP1 XMP."""
        pos = 2
        while pos < len(data) - 3:
            if data[pos] != 0xFF:
                break
            marker = data[pos:pos + 2]
            if len(data) < pos + 4:
                break
            length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            seg = data[pos + 4: pos + 2 + length]
            pos += 2 + length

            # APP1 — may contain XMP (if starts with XMP namespace)
            if marker == b"\xff\xe1" and seg.startswith(b"http://ns.adobe.com/xap/"):
                null_idx = seg.find(b"\x00")
                if null_idx != -1:
                    xmp_raw = seg[null_idx + 1:].decode("utf-8", errors="replace")
                    if not result.xmp:
                        result.xmp = _parse_xmp(xmp_raw)

            # APP13 — Photoshop IRB (contains IPTC-NAA)
            if marker == b"\xff\xed" and seg[:14] == b"Photoshop 3.0\x00":
                self._parse_photoshop_irb(seg[14:], result)

            if marker == b"\xff\xda":  # SOS — start of scan, no more headers
                break

    def _parse_photoshop_irb(self, data: bytes, result: MetadataResult) -> None:
        """Parse Photoshop Image Resource Blocks (IRB) — contains IPTC-NAA."""
        pos = 0
        while pos < len(data) - 7:
            if data[pos:pos+4] != b"8BIM":
                break
            resource_id = struct.unpack(">H", data[pos+4:pos+6])[0]
            # Pascal string for resource name (padded to even length)
            name_len = data[pos+6]
            name_end = pos + 7 + name_len
            if name_len % 2 == 0:
                name_end += 1  # padding byte
            resource_size = struct.unpack(">I", data[name_end:name_end+4])[0]
            resource_data = data[name_end+4: name_end+4+resource_size]
            pos = name_end + 4 + resource_size
            if resource_size % 2:
                pos += 1  # padding

            if resource_id == 0x0404:  # IPTC-NAA record
                result.iptc = _parse_iptc(resource_data)
            elif resource_id == 0x040F:  # ICC profile in Photoshop
                if not result.icc:
                    result.icc = _parse_icc(resource_data)

    # ── PNG ───────────────────────────────────────────────────────────────────

    def _read_png(self, data: bytes, result: MetadataResult) -> None:
        """Read PNG text chunks for XMP, EXIF, metadata."""
        pos = 8
        while pos < len(data) - 8:
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            chunk_data = data[pos+8:pos+8+length]
            pos += 12 + length

            if chunk_type == b"tEXt":
                null_idx = chunk_data.find(b"\x00")
                if null_idx != -1:
                    key = chunk_data[:null_idx].decode("latin-1")
                    val = chunk_data[null_idx+1:].decode("latin-1", errors="replace")
                    if key.lower() in ("comment", "description", "author", "copyright",
                                       "creation time", "software", "disclaimer", "warning",
                                       "source", "title"):
                        result.xmp[key] = val

            elif chunk_type == b"iTXt":
                null_idx = chunk_data.find(b"\x00")
                if null_idx != -1:
                    key = chunk_data[:null_idx].decode("utf-8", errors="replace")
                    if key.lower() == "xml:com.adobe.xmp":
                        rest = chunk_data[null_idx+1:]
                        for _ in range(3):
                            n = rest.find(b"\x00")
                            if n == -1:
                                break
                            rest = rest[n+1:]
                        result.xmp = _parse_xmp(rest.decode("utf-8", errors="replace"))

            elif chunk_type == b"gAMA":
                if len(chunk_data) == 4:
                    gamma = struct.unpack(">I", chunk_data)[0] / 100000
                    result.exif["Gamma"] = gamma

            elif chunk_type == b"pHYs":
                if len(chunk_data) == 9:
                    x, y, unit = struct.unpack(">IIB", chunk_data)
                    result.exif["XResolution"] = x
                    result.exif["YResolution"] = y
                    result.exif["ResolutionUnit"] = "meter" if unit == 1 else "unknown"

            elif chunk_type == b"IEND":
                break

        # Get dimensions from PIL
        try:
            img = Image.open(io.BytesIO(data))
            result.exif["ImageWidth"] = img.width
            result.exif["ImageHeight"] = img.height
            result.exif["ColorSpace"] = img.mode
        except Exception:
            pass

    # ── ID3 (MP3) ─────────────────────────────────────────────────────────────

    def _read_id3(self, data: bytes, result: MetadataResult) -> None:
        """
        Parse ID3v2 tags from MP3 files.
        Mirrors ExifTool's ID3 group.
        """
        if not data[:3] == b"ID3":
            return
        version = data[3]
        flags = data[5]
        # Syncsafe size: 4 bytes, each 7 bits
        size = (
            (data[6] & 0x7F) << 21 |
            (data[7] & 0x7F) << 14 |
            (data[8] & 0x7F) << 7  |
            (data[9] & 0x7F)
        )
        pos = 10
        end = 10 + size

        _id3_frames = {
            "TIT2": "Title", "TPE1": "Artist", "TALB": "Album",
            "TYER": "Year", "TRCK": "Track", "TCON": "Genre",
            "TCOM": "Composer", "TENC": "EncodedBy", "TCOP": "Copyright",
            "TLAN": "Language", "TBPM": "BPM", "COMM": "Comment",
            "TPUB": "Publisher", "TPE2": "AlbumArtist", "TIT3": "Subtitle",
            "TPOS": "DiscNumber", "TSRC": "ISRC",
        }

        while pos < end - 10:
            frame_id = data[pos:pos+4].decode("ascii", errors="replace")
            if not frame_id.strip() or frame_id[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                break
            frame_size = struct.unpack(">I", data[pos+4:pos+8])[0]
            frame_data = data[pos+10: pos+10+frame_size]
            pos += 10 + frame_size

            tag_name = _id3_frames.get(frame_id, frame_id)
            if frame_data and frame_data[0] in (0, 1, 2, 3):
                enc = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(
                    frame_data[0], "utf-8"
                )
                try:
                    text = frame_data[1:].decode(enc, errors="replace").strip("\x00").strip()
                    if text:
                        result.id3[tag_name] = text
                except Exception:
                    pass

        result.id3["ID3Version"] = f"2.{version}"

    # ── QuickTime / MP4 ───────────────────────────────────────────────────────

    def _read_quicktime(self, data: bytes, result: MetadataResult) -> None:
        """
        Parse QuickTime/MP4 metadata atoms.
        Mirrors ExifTool's QuickTime group.
        """
        _qt_tags = {
            b"\xa9nam": "Title", b"\xa9ART": "Artist", b"\xa9alb": "Album",
            b"\xa9day": "Year", b"\xa9cmt": "Comment", b"\xa9too": "Encoder",
            b"\xa9wrt": "Composer", b"cprt": "Copyright", b"desc": "Description",
            b"aART": "AlbumArtist", b"trkn": "Track", b"disk": "Disc",
            b"tmpo": "BPM", b"\xa9gen": "Genre", b"ldes": "LongDescription",
            b"\xa9lyr": "Lyrics",
        }

        def walk_atoms(buf: bytes, depth: int = 0) -> None:
            pos = 0
            while pos < len(buf) - 8:
                if len(buf) - pos < 8:
                    break
                box_size = struct.unpack(">I", buf[pos:pos+4])[0]
                box_type = buf[pos+4:pos+8]
                if box_size < 8 or box_size > len(buf) - pos:
                    break
                payload = buf[pos+8:pos+box_size]

                if box_type in (b"moov", b"udta", b"meta", b"ilst"):
                    # skip 4-byte version/flags for 'meta'
                    inner = payload[4:] if box_type == b"meta" else payload
                    walk_atoms(inner, depth + 1)
                elif box_type in _qt_tags:
                    # data atom inside: 8-byte header + value
                    if len(payload) > 16 and payload[4:8] == b"data":
                        val_bytes = payload[16:]
                        try:
                            result.quicktime[_qt_tags[box_type]] = val_bytes.decode(
                                "utf-8", errors="replace"
                            ).strip()
                        except Exception:
                            pass
                elif box_type == b"ftyp":
                    brand = payload[:4].decode("ascii", errors="replace")
                    result.quicktime["MajorBrand"] = brand

                pos += box_size

        walk_atoms(data)

    # ── PDF metadata ──────────────────────────────────────────────────────────

    def _read_pdf(self, data: bytes, result: MetadataResult) -> None:
        """Extract XMP and Info dict metadata from PDF."""
        # XMP stream
        xmp_start = data.find(b"<?xpacket")
        if xmp_start != -1:
            xmp_end = data.find(b"<?xpacket end", xmp_start)
            if xmp_end != -1:
                xmp_raw = data[xmp_start:xmp_end + 30].decode("utf-8", errors="replace")
                result.xmp = _parse_xmp(xmp_raw)

        # Info dict keys (naive scan for common patterns)
        _pdf_keys = {b"/Title": "Title", b"/Author": "Author",
                     b"/Subject": "Subject", b"/Keywords": "Keywords",
                     b"/Creator": "Creator", b"/Producer": "Producer",
                     b"/CreationDate": "CreateDate", b"/ModDate": "ModifyDate"}
        for key, tag in _pdf_keys.items():
            idx = data.find(key)
            if idx == -1:
                continue
            rest = data[idx + len(key):]
            m = re.search(rb"\(([^)]+)\)", rest[:200])
            if m:
                result.exif[tag] = m.group(1).decode("utf-8", errors="replace").strip()

    # ── Composite tags ────────────────────────────────────────────────────────

    def _compute_composite(self, result: MetadataResult) -> None:
        """
        Compute derived (Composite) tags from raw metadata.
        Mirrors ExifTool's Composite group — values derived from other tags.
        """
        # Aperture (FNumber → f/x.x)
        # Handle float, int, tuple, and PIL IFDRational all via try/float()
        fnumber = result.exif.get("FNumber")
        if fnumber is not None:
            try:
                val = fnumber[0] / fnumber[1] if isinstance(fnumber, tuple) else float(fnumber)
                if val > 0:
                    result.composite["Aperture"] = f"f/{val:.1f}"
            except Exception:
                pass

        # ShutterSpeed (ExposureTime → human readable)
        exp = result.exif.get("ExposureTime")
        if exp is not None:
            try:
                if isinstance(exp, tuple) and len(exp) == 2 and exp[1]:
                    num, den = exp
                    result.composite["ShutterSpeed"] = (
                        f"1/{round(den/num)}" if num == 1 or num < den else f"{num/den:.4f}"
                    )
                else:
                    t = float(exp)
                    if t > 0:
                        result.composite["ShutterSpeed"] = (
                            f"1/{round(1/t)}" if t < 1 else f"{t:.4f}s"
                        )
            except Exception:
                pass

        # FocalLength35efl (FocalLength + FocalLengthIn35mmFilm)
        fl = result.exif.get("FocalLengthIn35mmFilm")
        if fl:
            result.composite["FocalLength35efl"] = f"{fl}mm"

        # LightValue (LV = log2(FNumber^2 / ExposureTime * ISO / 100))
        iso = result.exif.get("ISOSpeedRatings") or result.exif.get("ISO")
        if fnumber and exp and iso:
            try:
                f = fnumber[0] / fnumber[1] if isinstance(fnumber, tuple) else float(fnumber)  # IFDRational also supports float()
                t = exp[0] / exp[1] if isinstance(exp, tuple) else float(exp)
                i = float(iso) if not isinstance(iso, tuple) else iso[0]
                import math
                lv = math.log2(f * f / t * i / 100)
                result.composite["LightValue"] = round(lv, 2)
            except Exception:
                pass

        # GPS coordinates formatted
        if result.gps and result.gps.latitude is not None:
            result.composite["GPSPosition"] = result.gps.coord_format("dms")

        # Megapixels
        w = result.exif.get("ImageWidth") or result.exif.get("ExifImageWidth")
        h = result.exif.get("ImageHeight") or result.exif.get("ExifImageLength")
        if w and h:
            mp = (w * h) / 1_000_000
            result.composite["Megapixels"] = round(mp, 2)

        # DateTimeCreated (EXIF CreateDate or DateTimeOriginal)
        for tag in ("DateTimeOriginal", "DateTime", "CreateDate"):
            dt = result.exif.get(tag)
            if dt:
                result.composite["DateTimeCreated"] = dt
                break


# ── Parsing utilities ─────────────────────────────────────────────────────────

def _decode_gps(gps_dict: dict) -> GPSInfo:
    """Decode PIL GPS dict into GPSInfo with decimal degrees."""
    gps = GPSInfo(raw=gps_dict)

    def _rational(val) -> Optional[float]:
        if isinstance(val, tuple) and len(val) == 2 and val[1]:
            return val[0] / val[1]
        if isinstance(val, (int, float)):
            return float(val)
        return None

    def _dms_to_decimal(dms_tuple, ref: str) -> Optional[float]:
        if not dms_tuple or len(dms_tuple) < 3:
            return None
        try:
            # PIL may return already-converted floats or rational tuples
            def _to_float(v):
                if isinstance(v, (int, float)):
                    return float(v)
                if isinstance(v, tuple) and len(v) == 2 and v[1]:
                    return v[0] / v[1]
                return float(v)
            d = _to_float(dms_tuple[0])
            m = _to_float(dms_tuple[1])
            s = _to_float(dms_tuple[2])
            decimal = d + m / 60 + s / 3600
            return -decimal if ref in ("S", "W") else decimal
        except Exception:
            return None

    lat_ref = gps_dict.get(GPSTAGS.get(1, 1), "N")
    lon_ref = gps_dict.get(GPSTAGS.get(3, 3), "E")

    # PIL returns GPS tuples keyed by tag ID number
    lat_raw = gps_dict.get(2)   # GPSLatitude
    lon_raw = gps_dict.get(4)   # GPSLongitude
    alt_raw = gps_dict.get(6)   # GPSAltitude
    dir_raw = gps_dict.get(17)  # GPSImgDirection
    spd_raw = gps_dict.get(13)  # GPSSpeed

    gps.latitude = _dms_to_decimal(lat_raw, lat_ref)
    gps.longitude = _dms_to_decimal(lon_raw, lon_ref)

    if alt_raw:
        gps.altitude = _rational(alt_raw)

    if dir_raw:
        gps.direction = _rational(dir_raw)

    if spd_raw:
        gps.speed = _rational(spd_raw)

    # GPS timestamp
    ts_time = gps_dict.get(7)  # GPSTimeStamp
    ts_date = gps_dict.get(29)  # GPSDateStamp
    if ts_time and ts_date:
        try:
            h = int(_rational(ts_time[0]) or 0)
            m = int(_rational(ts_time[1]) or 0)
            s = int(_rational(ts_time[2]) or 0)
            gps.timestamp = f"{ts_date} {h:02d}:{m:02d}:{s:02d} UTC"
        except Exception:
            pass

    return gps


def _parse_xmp(xmp_str: str) -> dict:
    """
    Extract key XMP properties from raw XMP XML string.
    Covers dc:, xmp:, photoshop:, xmpRights:, aux: namespaces.
    """
    tags: dict[str, Any] = {}
    # Common XMP property patterns
    patterns = [
        (r"<dc:title[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", "Title"),
        (r"<dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", "Creator"),
        (r"<dc:description[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", "Description"),
        (r"<dc:rights[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", "Rights"),
        (r"<dc:subject[^>]*>(.*?)</dc:subject>", "Keywords"),
        (r"<dc:format[^>]*>([^<]+)</dc:format>", "Format"),
        (r"<xmp:CreateDate[^>]*>([^<]+)</xmp:CreateDate>", "CreateDate"),
        (r"<xmp:ModifyDate[^>]*>([^<]+)</xmp:ModifyDate>", "ModifyDate"),
        (r"<xmp:CreatorTool[^>]*>([^<]+)</xmp:CreatorTool>", "CreatorTool"),
        (r"<xmp:Rating[^>]*>([^<]+)</xmp:Rating>", "Rating"),
        (r"<photoshop:Credit[^>]*>([^<]+)</photoshop:Credit>", "Credit"),
        (r"<photoshop:Source[^>]*>([^<]+)</photoshop:Source>", "Source"),
        (r"<photoshop:Headline[^>]*>([^<]+)</photoshop:Headline>", "Headline"),
        (r"<photoshop:City[^>]*>([^<]+)</photoshop:City>", "City"),
        (r"<photoshop:Country[^>]*>([^<]+)</photoshop:Country>", "Country"),
        (r"<xmpRights:Marked[^>]*>([^<]+)</xmpRights:Marked>", "RightsMarked"),
        (r"<xmpRights:WebStatement[^>]*>([^<]+)</xmpRights:WebStatement>", "WebStatement"),
        (r"<aux:Lens[^>]*>([^<]+)</aux:Lens>", "Lens"),
        (r"<aux:SerialNumber[^>]*>([^<]+)</aux:SerialNumber>", "SerialNumber"),
        (r'dc:title="([^"]+)"', "Title"),
        (r'dc:creator="([^"]+)"', "Creator"),
    ]
    for pattern, tag in patterns:
        m = re.search(pattern, xmp_str, re.DOTALL | re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            # Extract keyword list items
            if tag == "Keywords":
                kws = re.findall(r"<rdf:li[^>]*>([^<]+)</rdf:li>", val, re.IGNORECASE)
                if kws:
                    tags[tag] = kws
            elif val:
                tags[tag] = val
    return tags


def _parse_iptc(data: bytes) -> dict:
    """
    Parse IPTC-NAA binary record.
    Tags: record 2 (Application Record) — ObjectName, Keywords, Caption, etc.
    """
    _iptc_tags = {
        5: "ObjectName", 7: "EditStatus", 10: "Urgency", 15: "Category",
        20: "SupplementalCategories", 22: "FixtureIdentifier", 25: "Keywords",
        40: "SpecialInstructions", 55: "DateCreated", 60: "TimeCreated",
        62: "DigitizationDate", 80: "ByLine", 85: "ByLineTitle",
        90: "City", 92: "SubLocation", 95: "Province", 100: "CountryCode",
        101: "Country", 103: "OriginalTransmissionReference", 105: "Headline",
        110: "Credit", 115: "Source", 116: "Copyright", 118: "Contact",
        120: "Caption", 122: "CaptionWriter",
    }

    tags: dict[str, Any] = {}
    pos = 0
    while pos < len(data) - 4:
        if data[pos] != 0x1C:
            pos += 1
            continue
        record = data[pos + 1]
        dataset = data[pos + 2]
        length = struct.unpack(">H", data[pos + 3: pos + 5])[0]
        value = data[pos + 5: pos + 5 + length]
        pos += 5 + length

        if record == 2:
            tag_name = _iptc_tags.get(dataset, f"IPTC_{dataset}")
            try:
                decoded = value.decode("utf-8", errors="replace").strip()
            except Exception:
                decoded = repr(value)

            if tag_name in ("Keywords", "SupplementalCategories"):
                tags.setdefault(tag_name, []).append(decoded)
            else:
                tags[tag_name] = decoded

    return tags


def _parse_icc(data: bytes) -> dict:
    """Parse ICC color profile header fields."""
    if len(data) < 132:
        return {}
    _intents = {0: "Perceptual", 1: "Relative", 2: "Saturation", 3: "Absolute"}
    _classes = {
        b"scnr": "Scanner", b"mntr": "Monitor", b"prtr": "Printer",
        b"link": "DeviceLink", b"spac": "ColorSpace", b"abst": "Abstract",
        b"nmcl": "NamedColor",
    }
    _color_spaces = {
        b"XYZ ": "XYZ", b"Lab ": "CIELAB", b"Luv ": "CIELUV",
        b"YCbr": "YCbCr", b"Yxy ": "Yxy", b"RGB ": "RGB",
        b"GRAY": "Gray", b"HSV ": "HSV", b"HLS ": "HLS",
        b"CMYK": "CMYK",
    }
    try:
        return {
            "ProfileSize": struct.unpack(">I", data[0:4])[0],
            "ProfileClass": _classes.get(data[12:16], data[12:16].decode("ascii", errors="?")),
            "ColorSpaceData": _color_spaces.get(data[16:20], data[16:20].decode("ascii", errors="?")),
            "ProfileConnectionSpace": _color_spaces.get(data[20:24], "?"),
            "RenderingIntent": _intents.get(struct.unpack(">I", data[64:68])[0], "Unknown"),
            "ProfileDescription": _read_icc_tag_desc(data),
        }
    except Exception:
        return {}


def _read_icc_tag_desc(data: bytes) -> str:
    """Extract the 'desc' tag description string from ICC profile."""
    idx = data.find(b"desc")
    if idx == -1:
        return ""
    try:
        # Tag table entry: offset(4) + size(4)
        # Simple: find 'desc' signature in tag table
        offset = struct.unpack(">I", data[idx + 4:idx + 8])[0]
        size = struct.unpack(">I", data[idx + 8:idx + 12])[0]
        desc_data = data[offset:offset + size]
        if desc_data[:4] == b"desc":
            str_len = struct.unpack(">I", desc_data[8:12])[0]
            return desc_data[12:12 + str_len].decode("ascii", errors="replace").strip("\x00")
    except Exception:
        pass
    return ""


def _clean_value(value: Any) -> Any:
    """Convert PIL EXIF value types to JSON-serializable Python types."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").strip()
        except Exception:
            return value.hex()
    if isinstance(value, tuple) and len(value) == 2:
        # IFDRational — leave as fraction string
        if value[1] == 1:
            return value[0]
        if value[1] == 0:
            return None
        return f"{value[0]}/{value[1]}"
    if isinstance(value, tuple):
        return list(value)
    return value


def _guess_mime(data: bytes) -> str:
    """Guess MIME type from magic bytes."""
    if data[:2] == b"\xff\xd8":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[8:12] == b"WEBP":
        return "image/webp"
    if data[:4] == b"GIF8":
        return "image/gif"
    if data[:4] == b"%PDF":
        return "application/pdf"
    if data[:3] == b"ID3":
        return "audio/mpeg"
    if data[4:8] == b"ftyp":
        return "video/mp4"
    return "application/octet-stream"


def _deg_to_dms(deg: float) -> str:
    """Convert decimal degrees to deg min sec string."""
    d = int(deg)
    m = int((deg - d) * 60)
    s = (deg - d - m / 60) * 3600
    return f"{d}° {m}' {s:.2f}\""

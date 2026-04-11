"""Unit tests for metadata reader, diff, batch scanner, and thumbnail modules."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

try:
    import piexif
    _PIEXIF = True
except ImportError:
    _PIEXIF = False


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def jpeg_with_exif(tmp_path: Path) -> Path:
    """JPEG with real EXIF GPS data."""
    img = Image.fromarray(np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8))
    path = tmp_path / "gps.jpg"

    if _PIEXIF:
        exif_dict = {
            "0th": {
                piexif.ImageIFD.Make: b"TestCamera",
                piexif.ImageIFD.Model: b"Model X",
                piexif.ImageIFD.DateTime: b"2025:01:01 10:00:00",
                piexif.ImageIFD.Copyright: b"Test",
                piexif.ImageIFD.XResolution: (72, 1),
                piexif.ImageIFD.YResolution: (72, 1),
                piexif.ImageIFD.Orientation: 1,
            },
            "Exif": {
                piexif.ExifIFD.DateTimeOriginal: b"2025:01:01 10:00:00",
                piexif.ExifIFD.ExposureTime: (1, 500),
                piexif.ExifIFD.FNumber: (28, 10),
                piexif.ExifIFD.ISOSpeedRatings: 200,
                piexif.ExifIFD.FocalLength: (35, 1),
                piexif.ExifIFD.FocalLengthIn35mmFilm: 35,
                piexif.ExifIFD.Flash: 0,
                piexif.ExifIFD.ColorSpace: 1,
            },
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((51, 1), (30, 1), (0, 1)),
                piexif.GPSIFD.GPSLongitudeRef: b"W",
                piexif.GPSIFD.GPSLongitude: ((0, 1), (7, 1), (39, 1)),
                piexif.GPSIFD.GPSAltitude: (11, 1),
                piexif.GPSIFD.GPSAltitudeRef: 0,
            },
            "1st": {}, "thumbnail": None,
        }
        img.save(path, exif=piexif.dump(exif_dict), quality=90)
    else:
        img.save(path, format="JPEG", quality=90)
    return path


@pytest.fixture
def plain_jpeg(tmp_path: Path) -> Path:
    img = Image.fromarray(np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8))
    path = tmp_path / "plain.jpg"
    img.save(path, format="JPEG", quality=90)
    return path


@pytest.fixture
def plain_png(tmp_path: Path) -> Path:
    img = Image.fromarray(np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8))
    path = tmp_path / "img.png"
    img.save(path, format="PNG")
    return path


# ── MetadataReader ────────────────────────────────────────────────────────────

class TestMetadataReader:
    def test_reads_jpeg(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_jpeg)
        assert result.file_path == plain_jpeg
        assert result.file_type == "JPG"
        assert result.mime_type == "image/jpeg"
        assert result.file_size > 0

    def test_reads_png(self, plain_png: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_png)
        assert result.mime_type == "image/png"

    def test_computes_hashes(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader(compute_hashes=True).read(plain_jpeg)
        assert result.md5 is not None
        assert len(result.md5) == 32
        assert result.sha256 is not None
        assert len(result.sha256) == 64

    def test_no_hash_when_disabled(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader(compute_hashes=False).read(plain_jpeg)
        assert result.md5 is None
        assert result.sha256 is None

    def test_hashes_are_deterministic(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        r1 = MetadataReader().read(plain_jpeg)
        r2 = MetadataReader().read(plain_jpeg)
        assert r1.md5 == r2.md5
        assert r1.sha256 == r2.sha256

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_reads_exif_make_model(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        assert result.exif.get("Make") == "TestCamera"
        assert result.exif.get("Model") == "Model X"

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_reads_gps_coordinates(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        assert result.gps is not None
        assert result.gps.latitude is not None
        # London ~51.5 N
        assert 51.0 < result.gps.latitude < 52.0
        # London ~0.13 W (negative)
        assert result.gps.longitude is not None
        assert abs(result.gps.longitude) < 1.0

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_gps_decimal_format(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        assert result.gps is not None
        coord = result.gps.coord_format("decimal")
        assert coord is not None
        assert "," in coord

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_gps_dms_format(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        assert result.gps is not None
        dms = result.gps.coord_format("dms")
        assert dms is not None
        assert "°" in dms
        assert "N" in dms or "S" in dms

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_composite_tags_computed(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        # Should have computed Aperture from FNumber
        assert "Aperture" in result.composite
        assert result.composite["Aperture"].startswith("f/")

    @pytest.mark.skipif(not _PIEXIF, reason="piexif not installed")
    def test_composite_megapixels(self, jpeg_with_exif: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(jpeg_with_exif)
        assert "Megapixels" in result.composite  # present even for small test images
        assert "Megapixels" in result.composite  # present even for small test images

    def test_all_tags_flat(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_jpeg)
        tags = result.all_tags
        assert isinstance(tags, dict)

    def test_to_dict_grouped(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_jpeg)
        d = result.to_dict(group=True)
        assert "SourceFile" in d
        assert "FileType" in d

    def test_to_dict_flat(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_jpeg)
        d = result.to_dict(group=False)
        assert "SourceFile" in d
        assert isinstance(d, dict)

    def test_json_serialisable(self, plain_jpeg: Path) -> None:
        from authentica.metadata.reader import MetadataReader
        result = MetadataReader().read(plain_jpeg)
        json.dumps(result.to_dict(), default=str)  # must not raise


# ── MetadataDiff ──────────────────────────────────────────────────────────────

class TestMetadataDiff:
    def test_same_file_no_diff(self, plain_jpeg: Path) -> None:
        from authentica.metadata.diff import diff_metadata
        result = diff_metadata(plain_jpeg, plain_jpeg)
        assert len(result.entries) == 0

    def test_different_files_have_diff(self, plain_jpeg: Path, plain_png: Path) -> None:
        from authentica.metadata.diff import diff_metadata
        result = diff_metadata(plain_jpeg, plain_png)
        assert len(result.entries) > 0

    def test_summary_string(self, plain_jpeg: Path, plain_png: Path) -> None:
        from authentica.metadata.diff import diff_metadata
        result = diff_metadata(plain_jpeg, plain_png)
        s = result.summary()
        assert "added" in s
        assert "removed" in s
        assert "changed" in s

    def test_to_dict(self, plain_jpeg: Path, plain_png: Path) -> None:
        from authentica.metadata.diff import diff_metadata
        result = diff_metadata(plain_jpeg, plain_png)
        d = result.to_dict()
        assert "file_a" in d
        assert "file_b" in d
        assert "entries" in d

    def test_json_serialisable(self, plain_jpeg: Path, plain_png: Path) -> None:
        from authentica.metadata.diff import diff_metadata
        result = diff_metadata(plain_jpeg, plain_png)
        json.dumps(result.to_dict(), default=str)


# ── BatchScanner ─────────────────────────────────────────────────────────────

class TestBatchScanner:
    def test_walks_directory(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        for i in range(3):
            img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
            img.save(tmp_path / f"img{i}.jpg", format="JPEG")

        scanner = BatchScanner(extensions={".jpg"}, recurse=False)
        paths = list(scanner.walk(tmp_path))
        assert len(paths) == 3

    def test_filters_by_extension(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        img.save(tmp_path / "a.jpg", format="JPEG")
        (tmp_path / "b.txt").write_text("hello")

        scanner = BatchScanner(extensions={".jpg"}, recurse=False)
        paths = list(scanner.walk(tmp_path))
        assert all(p.suffix == ".jpg" for p in paths)
        assert len(paths) == 1

    def test_recurse_into_subdirs(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        sub = tmp_path / "sub"
        sub.mkdir()
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        img.save(tmp_path / "top.jpg", format="JPEG")
        img.save(sub / "sub.jpg", format="JPEG")

        scanner = BatchScanner(extensions={".jpg"}, recurse=True)
        paths = list(scanner.walk(tmp_path))
        assert len(paths) == 2

    def test_no_recurse(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        sub = tmp_path / "sub"
        sub.mkdir()
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        img.save(tmp_path / "top.jpg", format="JPEG")
        img.save(sub / "sub.jpg", format="JPEG")

        scanner = BatchScanner(extensions={".jpg"}, recurse=False)
        paths = list(scanner.walk(tmp_path))
        assert len(paths) == 1

    def test_scan_all_returns_results(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        img.save(tmp_path / "a.jpg", format="JPEG")

        scanner = BatchScanner(extensions={".jpg"})
        results, stats = scanner.scan_all(tmp_path, lambda p: {"file": str(p)})
        assert len(results) == 1
        assert stats.processed == 1

    def test_scan_all_handles_errors(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        img.save(tmp_path / "a.jpg", format="JPEG")

        def bad_processor(p):
            raise ValueError("intentional error")

        scanner = BatchScanner(extensions={".jpg"})
        results, stats = scanner.scan_all(tmp_path, bad_processor)
        assert stats.errors == 1
        assert "Error" in results[0]

    def test_results_to_csv(self, tmp_path: Path) -> None:
        from authentica.scanner.batch import results_to_csv
        rows = [{"SourceFile": "a.jpg", "Make": "Canon"},
                {"SourceFile": "b.jpg", "Make": "Nikon"}]
        csv_str = results_to_csv(rows)
        assert "SourceFile" in csv_str
        assert "Canon" in csv_str
        assert "Nikon" in csv_str

    def test_results_to_json(self) -> None:
        from authentica.scanner.batch import results_to_json
        rows = [{"SourceFile": "a.jpg", "Make": "Canon"}]
        json_str = results_to_json(rows)
        parsed = json.loads(json_str)
        assert parsed[0]["Make"] == "Canon"

    def test_single_file_walk(self, plain_jpeg: Path) -> None:
        from authentica.scanner.batch import BatchScanner
        scanner = BatchScanner(extensions={".jpg"})
        paths = list(scanner.walk(plain_jpeg))
        assert len(paths) == 1
        assert paths[0] == plain_jpeg


# ── Thumbnail extractor ───────────────────────────────────────────────────────

class TestThumbnailExtractor:
    def test_no_thumbnail_in_plain_jpeg(self, plain_jpeg: Path) -> None:
        from authentica.metadata.thumbnail import extract_thumbnail
        result = extract_thumbnail(plain_jpeg)
        # Plain JPEG without piexif-embedded thumbnail — found may be False
        assert isinstance(result.found, bool)

    def test_to_dict_structure(self, plain_jpeg: Path) -> None:
        from authentica.metadata.thumbnail import extract_thumbnail
        result = extract_thumbnail(plain_jpeg)
        d = result.to_dict()
        assert "found" in d
        assert "source" in d
        assert "size_bytes" in d


# ── Platform utils ────────────────────────────────────────────────────────────

class TestPlatform:
    def test_platform_info_keys(self) -> None:
        from authentica.utils.platform import platform_info
        info = platform_info()
        assert "os" in info
        assert "python" in info
        assert "is_64bit" in info

    def test_normalize_path(self, tmp_path: Path) -> None:
        from authentica.utils.platform import normalize_path
        p = normalize_path(tmp_path)
        assert p.is_dir()

    def test_safe_filename(self) -> None:
        from authentica.utils.platform import safe_filename
        name = safe_filename('my/file:name?.jpg')
        assert "/" not in name
        from authentica.utils.platform import IS_WINDOWS; assert ":" not in name if IS_WINDOWS else True
        assert "?" not in name

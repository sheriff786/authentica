"""Unit tests for authentica core and analyzers."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from authentica.core import scan, ScanResult
from authentica.c2pa.reader import C2PAReader, _iter_jumbf_boxes
from authentica.watermark.detector import WatermarkDetector, _dct2
from authentica.forensics.analyzer import ForensicsAnalyzer, _block_mean
from authentica.utils.file_type import detect_file_type, FileType


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_jpeg(tmp_path: Path) -> Path:
    """Create a minimal real JPEG image for testing."""
    img = Image.fromarray(
        np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
    )
    path = tmp_path / "sample.jpg"
    img.save(path, format="JPEG", quality=95)
    return path


@pytest.fixture
def sample_png(tmp_path: Path) -> Path:
    img = Image.fromarray(
        np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
    )
    path = tmp_path / "sample.png"
    img.save(path, format="PNG")
    return path


# ── File type detection ───────────────────────────────────────────────────────

class TestFileType:
    def test_detects_jpeg(self, sample_jpeg: Path) -> None:
        assert detect_file_type(sample_jpeg) == FileType.JPEG

    def test_detects_png(self, sample_png: Path) -> None:
        assert detect_file_type(sample_png) == FileType.PNG

    def test_detects_pdf(self, tmp_path: Path) -> None:
        path = tmp_path / "doc.pdf"
        path.write_bytes(b"%PDF-1.4 fake content")
        assert detect_file_type(path) == FileType.PDF

    def test_unknown_returns_octet_stream(self, tmp_path: Path) -> None:
        path = tmp_path / "random.bin"
        path.write_bytes(b"\x00\x01\x02\x03" * 10)
        assert detect_file_type(path) == FileType.UNKNOWN

    def test_extension_not_trusted(self, tmp_path: Path) -> None:
        # Name it .png but write JPEG magic bytes
        img = Image.fromarray(np.zeros((8, 8, 3), dtype=np.uint8))
        path = tmp_path / "fake.png"
        img.save(path, format="JPEG")
        assert detect_file_type(path) == FileType.JPEG


# ── C2PA Reader ───────────────────────────────────────────────────────────────

class TestC2PAReader:
    def test_no_manifest_jpeg(self, sample_jpeg: Path) -> None:
        result = C2PAReader().read(sample_jpeg)
        assert result.manifest_found is False
        assert result.signature_valid is False
        assert result.claims == []

    def test_no_manifest_png(self, sample_png: Path) -> None:
        result = C2PAReader().read(sample_png)
        assert result.manifest_found is False

    def test_result_to_dict(self, sample_jpeg: Path) -> None:
        result = C2PAReader().read(sample_jpeg)
        d = result.to_dict()
        assert "manifest_found" in d
        assert "signature_valid" in d
        assert "claims" in d

    def test_jumbf_iter_empty(self) -> None:
        boxes = list(_iter_jumbf_boxes(b""))
        assert boxes == []

    def test_jumbf_iter_too_short(self) -> None:
        boxes = list(_iter_jumbf_boxes(b"\x00\x00\x00\x09jumb"))
        # lbox=9, but payload only 1 byte → should break gracefully
        assert isinstance(boxes, list)


# ── Watermark Detector ────────────────────────────────────────────────────────

class TestWatermarkDetector:
    def test_runs_on_jpeg(self, sample_jpeg: Path) -> None:
        result = WatermarkDetector().detect(sample_jpeg)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.detected, bool)
        assert result.heatmap is not None

    def test_heatmap_shape_matches_image(self, sample_jpeg: Path) -> None:
        result = WatermarkDetector().detect(sample_jpeg)
        img = Image.open(sample_jpeg)
        w, h = img.size
        assert result.heatmap.shape == (h, w)

    def test_heatmap_values_in_range(self, sample_jpeg: Path) -> None:
        result = WatermarkDetector().detect(sample_jpeg)
        assert float(result.heatmap.min()) >= 0.0
        assert float(result.heatmap.max()) <= 1.0

    def test_to_dict_serialisable(self, sample_jpeg: Path) -> None:
        import json
        result = WatermarkDetector().detect(sample_jpeg)
        d = result.to_dict()
        json.dumps(d)  # must not raise

    def test_dct2_shape_preserved(self) -> None:
        block = np.random.rand(8, 8)
        out = _dct2(block)
        assert out.shape == (8, 8)


# ── Forensics Analyzer ────────────────────────────────────────────────────────

class TestForensicsAnalyzer:
    def test_runs_on_jpeg(self, sample_jpeg: Path) -> None:
        result = ForensicsAnalyzer().analyze(sample_jpeg)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_scores_in_range(self, sample_jpeg: Path) -> None:
        result = ForensicsAnalyzer().analyze(sample_jpeg)
        assert 0.0 <= result.ela_score <= 1.0
        assert 0.0 <= result.noise_score <= 1.0
        assert 0.0 <= result.frequency_score <= 1.0

    def test_ela_heatmap_shape(self, sample_jpeg: Path) -> None:
        result = ForensicsAnalyzer().analyze(sample_jpeg)
        img = Image.open(sample_jpeg)
        w, h = img.size
        assert result.ela_heatmap is not None
        assert result.ela_heatmap.shape == (h, w)

    def test_block_mean_shape(self) -> None:
        arr = np.ones((64, 64))
        out = _block_mean(arr, block_size=16)
        assert out.shape == (4, 4)
        assert float(np.mean(out)) == pytest.approx(1.0)

    def test_to_dict_complete(self, sample_jpeg: Path) -> None:
        result = ForensicsAnalyzer().analyze(sample_jpeg)
        d = result.to_dict()
        assert "anomaly_score" in d
        assert "ela_score" in d
        assert "noise_score" in d
        assert "frequency_score" in d


# ── Core scan ─────────────────────────────────────────────────────────────────

class TestScan:
    def test_scan_jpeg_returns_result(self, sample_jpeg: Path) -> None:
        result = scan(sample_jpeg)
        assert isinstance(result, ScanResult)

    def test_scan_trust_score_range(self, sample_jpeg: Path) -> None:
        result = scan(sample_jpeg)
        assert 0.0 <= result.trust_score <= 100.0

    def test_scan_summary_string(self, sample_jpeg: Path) -> None:
        result = scan(sample_jpeg)
        s = result.summary()
        assert "trust=" in s
        assert sample_jpeg.name in s

    def test_scan_to_dict(self, sample_jpeg: Path) -> None:
        import json
        result = scan(sample_jpeg)
        json.dumps(result.to_dict())  # must not raise

    def test_scan_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            scan("/nonexistent/path/image.jpg")

    def test_scan_skip_watermark(self, sample_jpeg: Path) -> None:
        result = scan(sample_jpeg, run_watermark=False)
        assert result.watermark is None

    def test_scan_skip_forensics(self, sample_jpeg: Path) -> None:
        result = scan(sample_jpeg, run_forensics=False)
        assert result.forensics is None

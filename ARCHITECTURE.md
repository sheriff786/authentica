# Authentica Architecture

This document gives a complete, end-to-end view of how Authentica is structured, how each component works, and how data flows through the system.

## 1) High-level overview

Authentica is a Python library and CLI for content authenticity analysis. It provides:
- Unified scan API that aggregates multiple analyzers.
- C2PA content credentials decoding.
- Passive watermark detection.
- Image forensics (ELA, noise residual, FFT artifacts).
- Metadata extraction (EXIF, IPTC, XMP, GPS, ICC, ID3, QuickTime).
- Metadata diff and batch scanning.

Core design principles:
- Trust file bytes, not extensions.
- Pure Python implementation, no external binaries.
- Modular analyzers with JSON-friendly output.
- CLI mirrors ExifTool-style workflows.

## 2) Package layout

Top-level:
- src/authentica/
  - core.py
  - c2pa/reader.py
  - watermark/detector.py
  - forensics/analyzer.py
  - metadata/reader.py
  - metadata/diff.py
  - metadata/thumbnail.py
  - scanner/batch.py
  - utils/file_type.py
  - utils/platform.py
  - cli/main.py
- examples/basic_usage.py
- tests/unit/

## 3) Unified scan pipeline (core.py)

Entry point: scan(path, run_c2pa=True, run_watermark=True, run_forensics=True)

Flow:
1) Detect file type via magic bytes (utils/file_type.py).
2) If enabled, run C2PA reader (c2pa/reader.py).
3) If image format, run watermark detector (watermark/detector.py).
4) If image format, run forensics analyzer (forensics/analyzer.py).
5) Aggregate into ScanResult:
   - file_path, file_type, scan_time_s
   - c2pa, watermark, forensics
   - errors (non-fatal per-module errors)
6) Compute trust_score (heuristic):
   - Base 50
   - +25 if C2PA valid
   - -20 if C2PA invalid
   - -40 * forensics.anomaly_score
   - +10 if watermark detected

ScanResult provides:
- summary(): human-readable one-line output
- to_dict(): JSON-safe output

## 4) CLI layer (cli/main.py)

The CLI is built with click and rich. Commands:
- scan: full authenticity scan (C2PA + watermark + forensics)
- meta: full metadata extraction
- c2pa: C2PA manifest decoding
- watermark: watermark detection
- forensics: forensics analysis
- diff: metadata diff
- scan-dir: batch scan directory
- thumbnail: extract embedded thumbnail
- version: platform info

Each command is a thin wrapper over the corresponding library component.
The CLI supports JSON/CSV outputs where appropriate.

## 5) C2PA decoder (c2pa/reader.py)

Purpose:
- Parse C2PA manifests from JPEG/PNG/PDF containers.
- Decode JUMBF boxes and CBOR payloads.
- Extract claims, assertions, and validation data.
- Produce ExifTool-like tags in JSON (exiftool_tags).

Key steps:
A) Extraction
- JPEG: walk APP11 segments with C2PA UUID.
- PNG: read caBX (binary JUMBF), iTXt/tEXt (base64 + optional zlib).
- PDF: locate C2PA UUID heuristic and read JUMBF box.

B) JUMBF parsing
- Parse JUMBF boxes into a tree (JumbfBox).
- Build path map for JUMBF URIs (self#jumbf=...).

C) Claim/Assertion decoding
- Decode CBOR payloads for c2pa.claim.v2, c2pa.actions.v2, c2pa.hash.data,
  c2pa.ingredient.v3, c2pa.thumbnail.ingredient, etc.
- Resolve assertions referenced by JUMBF URIs.

D) ExifTool-like tag mapping
- Flatten claim/assertion data into fields such as:
  - Actions Action
  - Claim Generator Info Name
  - Validation Results Active Manifest Success Code
  - C2PA Thumbnail Ingredient Type/Data

Outputs:
- C2PAResult with claims, assertions, warnings, and exiftool_tags.

## 6) Watermark detector (watermark/detector.py)

Purpose:
- Detect passive invisible watermarks without a reference image.

Techniques:
1) DCT anomaly scan
   - Block DCT on 8x8 blocks.
   - Inspect mid-frequency coefficients for abnormal energy.
2) DWT energy analysis
   - Wavelet decomposition (pywavelets).
   - Examine HH energy fraction vs baseline.
3) FFT spectrum peaks
   - Detect periodic peaks in frequency domain.

Outputs:
- WatermarkResult with confidence, per-method scores, heatmap.
- Optional heatmap save using matplotlib.

## 7) Forensics analyzer (forensics/analyzer.py)

Purpose:
- Detect AI/manipulation artifacts without a reference image.

Techniques:
1) Error Level Analysis (ELA)
   - Recompress to JPEG quality 90.
   - Measure per-pixel error and block inconsistency.
2) Noise residual analysis
   - Subtract smoothed image to get residual.
   - Measure residual autocorrelation.
3) Frequency domain anomaly
   - FFT magnitude cross patterns for GAN upsampling artifacts.

Outputs:
- ForensicsResult with anomaly score, component scores, heatmaps.
- Optional ELA/noise heatmap saving.

## 8) Metadata reader (metadata/reader.py)

Purpose:
- Extract metadata similar to ExifTool, pure Python.

Sources:
- EXIF via PIL
- GPS via EXIF GPS tags
- IPTC and Photoshop IRB via JPEG APP13
- XMP via APP1/iTXt
- ICC profiles
- ID3, QuickTime atoms
- Composite tags (Aperture, ShutterSpeed, Megapixels, etc.)

Outputs:
- MetadataResult with grouped tags and composite fields.
- MD5/SHA256 hashes (optional).

## 9) Metadata diff (metadata/diff.py)

Purpose:
- Compare two metadata snapshots.

Flow:
- Read both files with MetadataReader.
- Compute tag union and compare values.
- Produce added/removed/changed entries.

Outputs:
- MetadataDiff with entries + summary.

## 10) Thumbnail extraction (metadata/thumbnail.py)

Purpose:
- Extract embedded JPEG thumbnails (ExifTool-like behavior).

Sources:
- EXIF IFD1 thumbnail
- JFIF APP0 thumbnail
- Photoshop preview (if present)

Outputs:
- ThumbnailResult with source, dimensions, data, save/to_pil helpers.

## 11) Batch scanner (scanner/batch.py)

Purpose:
- Recursively scan directories and process files.

Capabilities:
- Extension filtering (ExifTool-style).
- Skip hidden/ignored directories.
- Optional progress output.
- Export results to CSV or JSON.

Outputs:
- List of dict results
- ScanStats (processed, errors, elapsed, rate)

## 12) Utilities

utils/file_type.py
- Magic-byte file type detection (no extension trust).
- Supports JPEG/PNG/WEBP/TIFF/GIF/PDF/MP4/MOV/HEIC.

utils/platform.py
- OS detection helpers.
- Safe filename normalization.
- platform_info for CLI version info.

## 13) Public API surface (__init__.py)

Exported symbols:
- scan, ScanResult
- C2PAReader
- WatermarkDetector
- ForensicsAnalyzer
- MetadataReader
- diff_metadata
- BatchScanner

Versioning:
- __version__ = 0.2.0

## 14) Tests (tests/unit)

- test_core.py
  - C2PA reader no-manifest cases
  - watermark and forensics smoke tests
  - scan result shape and trust score range

- test_metadata.py
  - metadata read + hashes
  - EXIF/GPS parsing (piexif optional)
  - diff results
  - batch scanner + thumbnail

## 15) Example usage (examples/basic_usage.py)

Provides runnable examples for:
- Full scan
- C2PA only
- Watermark only

## 16) Packaging

- pyproject.toml defines runtime deps and optional extras.
- CLI entry point: authentica = authentica.cli.main:cli
- requirements.txt mirrors runtime deps.

## 17) Data flow summary

File -> detect_file_type
  -> C2PAReader.read (optional)
  -> WatermarkDetector.detect (optional)
  -> ForensicsAnalyzer.analyze (optional)
  -> Aggregate ScanResult

Metadata flow:
File -> MetadataReader.read -> MetadataResult
  -> diff_metadata compares MetadataResults

Batch flow:
Directory -> BatchScanner.walk -> processor(Path) -> results_to_csv/json

## 18) Extension points

To add a new analyzer:
1) Create module under src/authentica/<new_module>
2) Add result dataclass with to_dict
3) Add analyzer class
4) Wire into core.scan and CLI
5) Add tests

To add a new file format:
- Update utils/file_type.py
- Extend metadata reader and/or c2pa decoder for new container

"""
Basic usage examples for the authentica library.

Run with:
    python examples/basic_usage.py path/to/image.jpg
"""

import sys
import json
from pathlib import Path

# If running from the repo root before installing:
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authentica import scan
from authentica.c2pa.reader import C2PAReader
from authentica.watermark.detector import WatermarkDetector
from authentica.forensics.analyzer import ForensicsAnalyzer


def example_full_scan(image_path: str) -> None:
    """Run the full unified scan and print results."""
    print(f"\n{'='*60}")
    print(f"  Full scan: {image_path}")
    print(f"{'='*60}")

    result = scan(image_path)

    print(result.summary())
    print(f"\nTrust score: {result.trust_score:.0f} / 100")

    if result.has_c2pa:
        print(f"\n✓ C2PA manifest found")
        print(f"  Generator : {result.c2pa.claim_generator}")
        print(f"  Signature : {'valid' if result.c2pa.signature_valid else 'INVALID'}")
        for assertion in result.c2pa.assertions:
            print(f"  Assertion : {assertion.label} — {assertion.description}")
    else:
        print("\n✗ No C2PA manifest")

    if result.watermark:
        status = "DETECTED" if result.watermark.detected else "not detected"
        print(f"\nWatermark: {status} (confidence {result.watermark.confidence:.0%})")

    if result.forensics:
        print(f"\nForensics anomaly: {result.forensics.anomaly_score:.0%}")
        print(f"  ELA score      : {result.forensics.ela_score:.0%}")
        print(f"  Noise score    : {result.forensics.noise_score:.0%}")
        print(f"  Frequency score: {result.forensics.frequency_score:.0%}")

    # Save heatmaps
    if result.watermark and result.watermark.heatmap is not None:
        result.watermark.save_heatmap("watermark_heatmap.png")
        print("\n→ Watermark heatmap saved: watermark_heatmap.png")

    if result.forensics:
        result.forensics.save_ela_heatmap("ela_heatmap.png")
        print("→ ELA heatmap saved: ela_heatmap.png")


def example_c2pa_only(image_path: str) -> None:
    """Read C2PA manifest only."""
    print(f"\n{'='*60}")
    print(f"  C2PA only: {image_path}")
    print(f"{'='*60}")

    reader = C2PAReader()
    result = reader.read(image_path)
    print(json.dumps(result.to_dict(), indent=2))


def example_watermark_only(image_path: str) -> None:
    """Run watermark detection only."""
    print(f"\n{'='*60}")
    print(f"  Watermark detection: {image_path}")
    print(f"{'='*60}")

    detector = WatermarkDetector()
    result = detector.detect(image_path)
    print(f"Detected: {result.detected}")
    print(f"Confidence: {result.confidence:.2%}")
    print(f"Methods: {result.method_scores}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python basic_usage.py path/to/image.jpg")
        sys.exit(1)

    path = sys.argv[1]
    example_full_scan(path)
    example_c2pa_only(path)
    example_watermark_only(path)

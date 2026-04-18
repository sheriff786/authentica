"""
Basic usage examples for the authentica library.

This file demonstrates three main patterns:
1. Individual analyzer usage (C2PA Reader, Watermark Detector, Forensics Analyzer)
2. Unified scan API (recommended for most use cases)
3. Batch processing from a folder

Installation:
    pip install authentica

Run examples:
    python examples/basic_usage.py --individual photo.jpg
    python examples/basic_usage.py --scan photo.jpg
    python examples/basic_usage.py --batch /path/to/image/folder
"""

import sys
from pathlib import Path

# If running from the repo root before installing, add src to path:
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authentica import scan
from authentica.c2pa import C2PAReader
from authentica.watermark import WatermarkDetector
from authentica.forensics import ForensicsAnalyzer
from authentica.scanner import BatchScanner


def example_individual_analyzers(image_path: str) -> None:
    """
    Use each analyzer individually.
    
    This is useful when you only need one type of analysis.
    """
    image_path = Path(image_path)
    
    if not image_path.exists():
        print(f"ERROR: Image not found: {image_path}")
        return
    
    print(f"\n{'='*70}")
    print(f"  INDIVIDUAL ANALYZER USAGE: {image_path.name}")
    print(f"{'='*70}")
    
    # C2PA Reader
    print("\n[1] C2PA Reader")
    print("-" * 70)
    try:
        c2pa_result = C2PAReader().read(image_path)
        print(f"  Claim Generator : {c2pa_result.claim_generator}")
        print(f"  Signature Valid : {c2pa_result.signature_valid}")
        print(f"  Assertions      : {len(c2pa_result.assertions)}")
        for assertion in c2pa_result.assertions[:3]:  # Show first 3
            print(f"    - {assertion.label}: {assertion.description}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Watermark Detector
    print("\n[2] Watermark Detector")
    print("-" * 70)
    try:
        wm_result = WatermarkDetector().detect(image_path)
        print(f"  Watermark Detected : {wm_result.detected}")
        print(f"  Confidence        : {wm_result.confidence:.0%}")
        print(f"  Heatmap Available : {wm_result.heatmap is not None}")
        
        if wm_result.detected:
            heatmap_path = image_path.parent / f"{image_path.stem}_wm_heatmap.png"
            wm_result.save_heatmap(heatmap_path)
            print(f"  Heatmap Saved     : {heatmap_path}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Forensics Analyzer
    print("\n[3] Forensics Analyzer")
    print("-" * 70)
    try:
        forensics_result = ForensicsAnalyzer().analyze(image_path)
        print(f"  Anomaly Score   : {forensics_result.anomaly_score:.0%}")
        print(f"  ELA Score       : {forensics_result.ela_score:.0%}")
        print(f"  Noise Score     : {forensics_result.noise_score:.0%}")
        print(f"  Frequency Score : {forensics_result.frequency_score:.0%}")
        
        if forensics_result.anomaly_score > 0.3:
            ela_path = image_path.parent / f"{image_path.stem}_ela_heatmap.png"
            noise_path = image_path.parent / f"{image_path.stem}_noise_heatmap.png"
            forensics_result.save_ela_heatmap(ela_path)
            forensics_result.save_noise_heatmap(noise_path)
            print(f"  ELA Heatmap     : {ela_path}")
            print(f"  Noise Heatmap   : {noise_path}")
    except Exception as e:
        print(f"  Error: {e}")


def example_unified_scan(image_path: str) -> None:
    """
    Use the unified scan API (recommended).
    
    This runs all analyzers and aggregates results with a trust score.
    """
    image_path = Path(image_path)
    
    if not image_path.exists():
        print(f"ERROR: Image not found: {image_path}")
        return
    
    print(f"\n{'='*70}")
    print(f"  UNIFIED SCAN: {image_path.name}")
    print(f"{'='*70}")
    
    try:
        result = scan(image_path)
        print(result.summary())
        print(f"\nTrust Score: {result.trust_score:.0f} / 100")
        
        if result.has_c2pa:
            print(f"\n✓ C2PA Manifest Found")
            print(f"  Generator: {result.c2pa.claim_generator}")
            print(f"  Signature: {'VALID' if result.c2pa.signature_valid else 'INVALID'}")
        else:
            print(f"\n✗ No C2PA Manifest")
        
        if result.watermark and result.watermark.detected:
            print(f"\n✓ Watermark Detected (confidence {result.watermark.confidence:.0%})")
        
        if result.forensics and result.forensics.anomaly_score > 0.5:
            print(f"\n⚠ High Anomaly Score: {result.forensics.anomaly_score:.0%}")
    except Exception as e:
        print(f"Error: {e}")


def example_batch_processing(folder_path: str) -> None:
    """
    Process multiple images from a folder.
    
    Recursively scans for images and processes them in batch.
    """
    folder_path = Path(folder_path)
    
    if not folder_path.exists():
        print(f"ERROR: Folder not found: {folder_path}")
        return
    
    print(f"\n{'='*70}")
    print(f"  BATCH PROCESSING: {folder_path}")
    print(f"{'='*70}")
    
    # Create a scanner that processes .jpg and .png files recursively
    scanner = BatchScanner(extensions={".jpg", ".jpeg", ".png"}, recurse=True)
    
    results_summary = {
        "total": 0,
        "has_c2pa": 0,
        "watermark_detected": 0,
        "high_anomaly": 0,
    }
    
    print(f"\nScanning for images in {folder_path}...\n")
    
    for image_path in scanner.walk(folder_path):
        results_summary["total"] += 1
        print(f"Processing: {image_path.relative_to(folder_path)}")
        
        try:
            result = scan(image_path)
            
            if result.has_c2pa:
                results_summary["has_c2pa"] += 1
                print(f"  ✓ C2PA: {result.c2pa.claim_generator}")
            
            if result.watermark and result.watermark.detected:
                results_summary["watermark_detected"] += 1
                print(f"  ~ Watermark: {result.watermark.confidence:.0%} confidence")
            
            if result.forensics and result.forensics.anomaly_score > 0.5:
                results_summary["high_anomaly"] += 1
                print(f"  ⚠ Anomaly: {result.forensics.anomaly_score:.0%}")
        
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"  BATCH SUMMARY")
    print(f"{'='*70}")
    print(f"Total images    : {results_summary['total']}")
    print(f"C2PA found      : {results_summary['has_c2pa']}")
    print(f"Watermarks      : {results_summary['watermark_detected']}")
    print(f"High anomaly    : {results_summary['high_anomaly']}")


if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                         AUTHENTICA - Usage Examples                        ║
║                   AI Content Authenticity Detection Library                ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("USAGE:")
        print("  python examples/basic_usage.py --individual <image_path>")
        print("    → Run C2PA, Watermark, and Forensics individually\n")
        print("  python examples/basic_usage.py --scan <image_path>")
        print("    → Run unified scan (recommended)\n")
        print("  python examples/basic_usage.py --batch <folder_path>")
        print("    → Process all images in a folder recursively\n")
        print("EXAMPLES:")
        print("  python examples/basic_usage.py --scan my_photo.jpg")
        print("  python examples/basic_usage.py --batch ./image_folder")
        sys.exit(1)
    
    mode = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not target:
        print(f"ERROR: {mode} requires a path argument")
        sys.exit(1)
    
    if mode == "--individual":
        example_individual_analyzers(target)
    elif mode == "--scan":
        example_unified_scan(target)
    elif mode == "--batch":
        example_batch_processing(target)
    else:
        print(f"ERROR: Unknown mode '{mode}'. Use --individual, --scan, or --batch")
        sys.exit(1)

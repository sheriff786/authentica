"""Test the exact code snippet you provided."""

from authentica.c2pa import C2PAReader
from authentica.watermark import WatermarkDetector
from authentica.forensics import ForensicsAnalyzer

test_image = "images/sora_image.png"

print(f"Testing with: {test_image}\n")

# C2PA only
print("=" * 70)
print("[1] C2PA Reader")
print("=" * 70)
try:
    c2pa = C2PAReader().read(test_image)
    print(f"Claim Generator: {c2pa.claim_generator}")
    print(f"Signature Valid: {c2pa.signature_valid}")
except Exception as e:
    print(f"Error: {e}")

# Watermark only
print("\n" + "=" * 70)
print("[2] Watermark Detector")
print("=" * 70)
try:
    wm = WatermarkDetector().detect(test_image)
    print(f"Watermark: {wm.detected}  confidence: {wm.confidence:.0%}")
    wm.save_heatmap("wm_heatmap.png")
    print(f"Heatmap saved: wm_heatmap.png")
except Exception as e:
    print(f"Error: {e}")

# Forensics only
print("\n" + "=" * 70)
print("[3] Forensics Analyzer")
print("=" * 70)
try:
    forensics = ForensicsAnalyzer().analyze(test_image)
    print(f"Anomaly score: {forensics.anomaly_score:.0%}")
    forensics.save_ela_heatmap("ela_heatmap.png")
    forensics.save_noise_heatmap("noise_heatmap.png")
    print(f"ELA heatmap saved: ela_heatmap.png")
    print(f"Noise heatmap saved: noise_heatmap.png")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 70)
print("✓ All tests completed!")
print("=" * 70)

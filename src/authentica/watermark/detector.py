"""
Passive invisible watermark detector.

Detects invisible (blind) watermarks embedded in images using
frequency-domain analysis — no knowledge of the original image needed.

Three complementary techniques are applied:
  1. DCT coefficient anomaly scan  — detects mid-frequency energy bumps
     typical of JPEG-domain watermark embedding (like StegaStamp, TreeRing).
  2. DWT subband energy analysis   — wavelet decomposition reveals spatial
     energy redistribution left by DWT-domain watermarks.
  3. FFT magnitude spectrum peaks  — sharp peaks in the Fourier spectrum
     often signal periodic watermark patterns.

Each technique returns a per-pixel influence map (heatmap).
The combined heatmap is the normalised average of all maps.

References / inspiration:
  - invisible-watermark library (ShieldMnt/invisible-watermark)
  - "Robust Invisible Watermarking" (Fernandez et al., 2023)
  - ExifTool's pixel-level analysis approach
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image

try:
    import pywt
    _PWT_AVAILABLE = True
except ImportError:
    _PWT_AVAILABLE = False


# Detection threshold: combined score above this → watermark suspected
_DETECTION_THRESHOLD = 0.35

# DCT block size (JPEG uses 8×8)
_DCT_BLOCK = 8


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class WatermarkResult:
    """
    Result of passive watermark detection on a single image.

    Attributes:
        detected:       True if a watermark signal was found.
        confidence:     0-1 confidence score.
        method_scores:  Per-method confidence scores.
        heatmap:        2-D numpy array (same H×W as input image, values 0-1).
                        High values = high suspicion of watermark influence.
        warnings:       Non-fatal messages (e.g., library not available).
    """
    detected: bool
    confidence: float
    method_scores: dict[str, float]
    heatmap: Optional[np.ndarray] = field(default=None, repr=False)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "confidence": round(self.confidence, 4),
            "method_scores": {k: round(v, 4) for k, v in self.method_scores.items()},
            "heatmap_shape": list(self.heatmap.shape) if self.heatmap is not None else None,
            "warnings": self.warnings,
        }

    def save_heatmap(self, path: str | Path, overlay_alpha: float = 0.6) -> None:
        """
        Save the watermark heatmap as a PNG image.

        Args:
            path:          Output file path.
            overlay_alpha: Opacity of the heatmap overlay (0=transparent, 1=opaque).
        """
        if self.heatmap is None:
            raise ValueError("No heatmap available")
        try:
            import matplotlib.pyplot as plt
            import matplotlib.cm as cm
            fig, ax = plt.subplots(figsize=(8, 8), dpi=100)
            im = ax.imshow(self.heatmap, cmap="inferno", vmin=0, vmax=1)
            plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Watermark influence score")
            ax.set_title(
                f"Watermark heatmap  —  confidence: {self.confidence:.2%}",
                fontsize=12,
            )
            ax.axis("off")
            plt.tight_layout()
            plt.savefig(path, bbox_inches="tight", dpi=150)
            plt.close(fig)
        except ImportError:
            raise ImportError("matplotlib is required to save heatmaps: pip install matplotlib")


# ── Detector ──────────────────────────────────────────────────────────────────

class WatermarkDetector:
    """
    Detect passive invisible watermarks in images.

    No reference image needed (blind detection).
    Works on JPEG, PNG, WebP, TIFF.

    Usage:
        detector = WatermarkDetector()
        result = detector.detect("image.jpg")
        if result.detected:
            print(f"Watermark suspected — confidence {result.confidence:.0%}")
            result.save_heatmap("heatmap.png")
    """

    def detect(self, path: Path) -> WatermarkResult:
        """Run all detection methods and aggregate results."""
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)
        gray = np.mean(arr, axis=2)  # luminance channel

        warnings: list[str] = []
        method_scores: dict[str, float] = {}
        heatmaps: list[np.ndarray] = []

        # --- Method 1: DCT coefficient anomaly ---
        dct_score, dct_heatmap = self._dct_anomaly(gray)
        method_scores["dct"] = dct_score
        heatmaps.append(dct_heatmap)

        # --- Method 2: DWT subband energy ---
        if _PWT_AVAILABLE:
            dwt_score, dwt_heatmap = self._dwt_energy(gray)
            method_scores["dwt"] = dwt_score
            heatmaps.append(dwt_heatmap)
        else:
            warnings.append("pywavelets not installed; DWT analysis skipped. pip install PyWavelets")

        # --- Method 3: FFT spectrum peaks ---
        fft_score, fft_heatmap = self._fft_peaks(gray)
        method_scores["fft"] = fft_score
        heatmaps.append(fft_heatmap)

        # --- Combine heatmaps (resize all to same shape, then average) ---
        h, w = gray.shape
        combined = np.zeros((h, w), dtype=np.float64)
        for hm in heatmaps:
            if hm.shape != (h, w):
                hm = _resize_heatmap(hm, (h, w))
            combined += hm
        combined /= len(heatmaps)
        combined = np.clip(combined, 0.0, 1.0)

        # Overall confidence = weighted average of method scores
        weights = {"dct": 0.4, "dwt": 0.35, "fft": 0.25}
        total_w = sum(weights[k] for k in method_scores)
        confidence = sum(
            method_scores[k] * weights[k] for k in method_scores
        ) / total_w

        detected = confidence >= _DETECTION_THRESHOLD

        return WatermarkResult(
            detected=detected,
            confidence=confidence,
            method_scores=method_scores,
            heatmap=combined,
            warnings=warnings,
        )

    # ── DCT analysis ──────────────────────────────────────────────────────────

    def _dct_anomaly(self, gray: np.ndarray) -> tuple[float, np.ndarray]:
        """
        Block DCT analysis.

        Watermarks embedded in the DCT domain (like JPEG steganography)
        leave characteristic energy patterns in mid-frequency coefficients.
        We compute the variance of mid-frequency DCT coefficients per block
        and compare to the expected variance of natural image blocks.

        Returns: (anomaly_score 0-1, per-pixel heatmap)
        """
        h, w = gray.shape
        bh = (h // _DCT_BLOCK) * _DCT_BLOCK
        bw = (w // _DCT_BLOCK) * _DCT_BLOCK
        cropped = gray[:bh, :bw]

        n_rows = bh // _DCT_BLOCK
        n_cols = bw // _DCT_BLOCK
        block_scores = np.zeros((n_rows, n_cols), dtype=np.float64)

        for r in range(n_rows):
            for c in range(n_cols):
                block = cropped[
                    r * _DCT_BLOCK : (r + 1) * _DCT_BLOCK,
                    c * _DCT_BLOCK : (c + 1) * _DCT_BLOCK,
                ]
                dct_block = _dct2(block - 128.0)
                # Mid-frequency coefficients: zig-zag positions 5-20
                flat = dct_block.flatten()
                mid = flat[5:21]
                # Measure deviation from expected natural-image energy
                block_scores[r, c] = float(np.std(mid) / (np.mean(np.abs(flat)) + 1e-6))

        # Normalise block scores to 0-1
        min_s, max_s = block_scores.min(), block_scores.max()
        if max_s > min_s:
            norm = (block_scores - min_s) / (max_s - min_s)
        else:
            norm = block_scores

        # Upsample block map back to pixel resolution
        heatmap = np.kron(norm, np.ones((_DCT_BLOCK, _DCT_BLOCK), dtype=np.float64))
        heatmap = _pad_to(heatmap, (h, w))

        # Score = fraction of blocks with anomalously high mid-frequency energy
        threshold_95 = float(np.percentile(block_scores, 95))
        anomaly_frac = float(np.mean(block_scores > threshold_95 * 0.6))
        score = min(anomaly_frac * 3.0, 1.0)

        return score, heatmap

    # ── DWT analysis ─────────────────────────────────────────────────────────

    def _dwt_energy(self, gray: np.ndarray) -> tuple[float, np.ndarray]:
        """
        DWT subband energy analysis.

        DWT-domain watermarks (e.g., dwtDct, dwtDctSvd in invisible-watermark)
        alter the energy distribution across LL/LH/HL/HH subbands.
        Natural images have a characteristic 1/f energy slope; watermarked
        images often show elevated HH energy relative to this baseline.
        """
        coeffs = pywt.dwt2(gray, "haar")
        cA, (cH, cV, cD) = coeffs

        # Energy in each subband
        e_ll = float(np.mean(cA ** 2))
        e_lh = float(np.mean(cH ** 2))
        e_hl = float(np.mean(cV ** 2))
        e_hh = float(np.mean(cD ** 2))

        total = e_ll + e_lh + e_hl + e_hh + 1e-9

        # Natural images: HH fraction is typically < 0.02
        # Watermarked images often show 0.04-0.08 HH fraction
        hh_fraction = e_hh / total
        # Score: how far above the natural baseline (0.02) are we?
        score = min(max((hh_fraction - 0.02) / 0.08, 0.0), 1.0)

        # Heatmap from detail subband absolute values
        detail_energy = np.abs(cH) + np.abs(cV) + np.abs(cD)
        de_min, de_max = detail_energy.min(), detail_energy.max()
        if de_max > de_min:
            heatmap = (detail_energy - de_min) / (de_max - de_min)
        else:
            heatmap = detail_energy

        return score, heatmap

    # ── FFT analysis ──────────────────────────────────────────────────────────

    def _fft_peaks(self, gray: np.ndarray) -> tuple[float, np.ndarray]:
        """
        FFT magnitude spectrum peak detection.

        Periodic watermarks (e.g., Stable Diffusion's watermark, TreeRing)
        appear as discrete spikes in the Fourier magnitude spectrum.
        Natural image spectra are smooth 1/f without sharp isolated peaks.

        We detect peaks as deviations significantly above the local median.
        """
        fft = np.fft.fft2(gray)
        magnitude = np.abs(np.fft.fftshift(fft))
        log_mag = np.log1p(magnitude)

        h, w = log_mag.shape

        # Local median filter to find background level
        from scipy.ndimage import median_filter, uniform_filter  # type: ignore
        background = median_filter(log_mag, size=15)
        residual = log_mag - background

        # Peaks: residual above 2.5 standard deviations
        sigma = float(np.std(residual))
        peak_mask = residual > 2.5 * sigma

        # Exclude DC component and very low frequencies (centre 5%)
        cy, cx = h // 2, w // 2
        r = int(min(h, w) * 0.05)
        peak_mask[cy - r : cy + r, cx - r : cx + r] = False

        peak_frac = float(np.mean(peak_mask))
        # Score: fraction of spectrum that is anomalous peaks
        score = min(peak_frac * 500.0, 1.0)

        # Heatmap: back-project peaks to spatial domain via inverse FFT
        filtered = np.fft.ifftshift(np.fft.ifftshift(peak_mask.astype(np.float64)))
        spatial = np.abs(np.fft.ifft2(filtered * fft))
        s_min, s_max = spatial.min(), spatial.max()
        if s_max > s_min:
            heatmap = (spatial - s_min) / (s_max - s_min)
        else:
            heatmap = np.zeros_like(spatial)

        return score, heatmap


# ── Utility functions ─────────────────────────────────────────────────────────

def _dct2(block: np.ndarray) -> np.ndarray:
    """2D Discrete Cosine Transform via the separable property."""
    from scipy.fftpack import dct  # type: ignore
    return dct(dct(block, axis=0, norm="ortho"), axis=1, norm="ortho")


def _resize_heatmap(heatmap: np.ndarray, target_shape: tuple[int, int]) -> np.ndarray:
    """Resize a heatmap array to target_shape using PIL nearest-neighbour."""
    img = Image.fromarray((heatmap * 255).astype(np.uint8))
    resized = img.resize((target_shape[1], target_shape[0]), Image.NEAREST)
    return np.array(resized, dtype=np.float64) / 255.0


def _pad_to(arr: np.ndarray, target_shape: tuple[int, int]) -> np.ndarray:
    """Zero-pad or crop arr to exactly target_shape."""
    th, tw = target_shape
    ah, aw = arr.shape
    out = np.zeros((th, tw), dtype=arr.dtype)
    out[: min(ah, th), : min(aw, tw)] = arr[: min(ah, th), : min(aw, tw)]
    return out

"""
Image forensics analyzer.

Applies multiple passive forensics techniques to detect AI-generated
or manipulated images. No reference image is needed.

Techniques:
  1. Error Level Analysis (ELA)  — resave the image at known quality,
     measure per-pixel error. Authentic JPEG regions show uniform error;
     composited/AI regions often show distinct error levels.

  2. Noise residual analysis — extract the camera noise fingerprint
     via a denoising filter. AI-generated images lack the structured
     sensor noise of real cameras (they often show patterned artifacts
     instead). We measure the statistical regularity of the residual.

  3. Frequency domain anomaly — GAN and diffusion models often leave
     characteristic artifacts in the high-frequency part of the spectrum
     (e.g., GAN upsampling grid artifacts at N×N pixel periods).
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image


# ELA re-compression quality level
_ELA_QUALITY = 90

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ForensicsResult:
    """
    Result of forensics analysis on a single image.

    Attributes:
        anomaly_score:      0-1 overall anomaly score. 0 = natural, 1 = highly anomalous.
        ela_score:          ELA inconsistency score.
        noise_score:        Noise residual anomaly score.
        frequency_score:    Frequency domain anomaly score.
        ela_heatmap:        Per-pixel ELA error map (H×W, float 0-1).
        noise_heatmap:      Per-pixel noise residual map (H×W, float 0-1).
        warnings:           Non-fatal analysis messages.
    """
    anomaly_score: float
    ela_score: float
    noise_score: float
    frequency_score: float
    ela_heatmap: Optional[np.ndarray] = field(default=None, repr=False)
    noise_heatmap: Optional[np.ndarray] = field(default=None, repr=False)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "anomaly_score": round(self.anomaly_score, 4),
            "ela_score": round(self.ela_score, 4),
            "noise_score": round(self.noise_score, 4),
            "frequency_score": round(self.frequency_score, 4),
            "warnings": self.warnings,
        }

    def save_ela_heatmap(self, path: str | Path) -> None:
        """Save the ELA heatmap as a PNG."""
        _save_heatmap(
            self.ela_heatmap,
            path,
            title=f"ELA heatmap  —  anomaly: {self.ela_score:.2%}",
            cmap="hot",
        )

    def save_noise_heatmap(self, path: str | Path) -> None:
        """Save the noise residual heatmap as a PNG."""
        _save_heatmap(
            self.noise_heatmap,
            path,
            title=f"Noise residual  —  anomaly: {self.noise_score:.2%}",
            cmap="viridis",
        )


# ── Analyzer ──────────────────────────────────────────────────────────────────

class ForensicsAnalyzer:
    """
    Multi-technique image forensics analyzer.

    Applies ELA, noise residual, and frequency-domain analysis
    to detect AI-generated or manipulated image regions.

    Usage:
        analyzer = ForensicsAnalyzer()
        result = analyzer.analyze("photo.jpg")
        print(f"Anomaly score: {result.anomaly_score:.2%}")
        result.save_ela_heatmap("ela.png")
    """

    def analyze(self, path: Path) -> ForensicsResult:
        """Run all forensics techniques and aggregate results."""
        img = Image.open(path).convert("RGB")
        arr = np.array(img, dtype=np.float64)
        gray = np.mean(arr, axis=2)
        warnings: list[str] = []

        # --- ELA ---
        ela_score, ela_heatmap = self._ela(img, path, warnings)

        # --- Noise residual ---
        noise_score, noise_heatmap = self._noise_residual(gray)

        # --- Frequency domain ---
        freq_score = self._frequency_anomaly(gray)

        # Combined anomaly score (weighted)
        anomaly = (
            ela_score * 0.45
            + noise_score * 0.35
            + freq_score * 0.20
        )
        anomaly = min(anomaly, 1.0)

        return ForensicsResult(
            anomaly_score=anomaly,
            ela_score=ela_score,
            noise_score=noise_score,
            frequency_score=freq_score,
            ela_heatmap=ela_heatmap,
            noise_heatmap=noise_heatmap,
            warnings=warnings,
        )

    # ── Error Level Analysis ──────────────────────────────────────────────────

    def _ela(
        self,
        img: Image.Image,
        path: Path,
        warnings: list[str],
    ) -> tuple[float, np.ndarray]:
        """
        Error Level Analysis.

        Resave the image at quality=90, compute per-pixel absolute difference.
        Uniform authentic regions: low, consistent error.
        Spliced / AI regions: distinctly different error levels.

        Works best on JPEG; for PNG we apply JPEG compression first.
        """
        # Re-save to in-memory JPEG at known quality
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=_ELA_QUALITY)
        buf.seek(0)
        recompressed = Image.open(buf).convert("RGB")

        orig = np.array(img, dtype=np.float64)
        recomp = np.array(recompressed, dtype=np.float64)

        # Per-pixel error (mean across channels)
        error = np.mean(np.abs(orig - recomp), axis=2)

        # Amplify for visibility
        amplified = np.clip(error * 10.0, 0, 255)
        heatmap = amplified / 255.0

        # Score: coefficient of variation of ELA error.
        # Natural images: low CV (uniform error per compression level).
        # Composited images: high CV (different regions at different error levels).
        mean_err = float(np.mean(error)) + 1e-9
        std_err = float(np.std(error))
        cv = std_err / mean_err

        # Also measure block-level inconsistency
        block_means = _block_mean(error, block_size=16)
        block_cv = float(np.std(block_means)) / (float(np.mean(block_means)) + 1e-9)

        score = min((cv * 0.5 + block_cv * 0.5) / 2.0, 1.0)
        return score, heatmap

    # ── Noise residual ────────────────────────────────────────────────────────

    def _noise_residual(self, gray: np.ndarray) -> tuple[float, np.ndarray]:
        """
        Camera noise residual analysis.

        Real camera images have structured sensor noise (PRNU).
        AI-generated images either have no noise, synthetic noise
        patterns, or regular artifacts from upsampling.

        We extract the noise residual via a simple denoising filter
        (box blur subtraction) and analyse its statistical properties.
        """
        from scipy.ndimage import uniform_filter  # type: ignore

        # Denoised approximation via Gaussian-like box filter
        smoothed = uniform_filter(gray, size=3)
        residual = gray - smoothed

        # Heatmap from residual magnitude
        abs_res = np.abs(residual)
        r_min, r_max = abs_res.min(), abs_res.max()
        if r_max > r_min:
            heatmap = (abs_res - r_min) / (r_max - r_min)
        else:
            heatmap = np.zeros_like(abs_res)

        # Score via autocorrelation of residual
        # Natural noise: low autocorrelation (nearly i.i.d.)
        # AI/GAN artifacts: periodic → high autocorrelation at small lags
        flat = residual.flatten()
        n = len(flat)
        if n > 1024:
            flat = flat[:1024]  # sample for speed
        acf1 = float(np.corrcoef(flat[:-1], flat[1:])[0, 1])  # lag-1 autocorrelation
        # High |acf1| → periodic structure → anomaly
        score = min(abs(acf1) * 2.0, 1.0)

        return score, heatmap

    # ── Frequency domain ──────────────────────────────────────────────────────

    def _frequency_anomaly(self, gray: np.ndarray) -> float:
        """
        GAN upsampling grid detection via FFT.

        GAN models using nearest-neighbour or bilinear upsampling
        often leave periodic grid artifacts at spatial frequencies
        corresponding to the upsampling factor (commonly 2×, 4×, 8×).
        These show as cross-shaped spikes in the Fourier spectrum.
        """
        fft = np.fft.fft2(gray)
        magnitude = np.abs(np.fft.fftshift(fft))
        log_mag = np.log1p(magnitude)

        h, w = log_mag.shape
        cy, cx = h // 2, w // 2

        # Sum energy along horizontal and vertical axes (cross pattern)
        row_axis = log_mag[cy, :]
        col_axis = log_mag[:, cx]

        # Remove DC component
        row_axis = row_axis.copy()
        col_axis = col_axis.copy()
        row_axis[cx - 3 : cx + 4] = 0
        col_axis[cy - 3 : cy + 4] = 0

        # Background level = median of off-axis pixels
        off_axis = np.concatenate([
            log_mag[cy - 5, :], log_mag[cy + 5, :],  # nearby rows
            log_mag[:, cx - 5], log_mag[:, cx + 5],  # nearby cols
        ])
        bg = float(np.median(off_axis))

        row_excess = float(np.mean(np.maximum(row_axis - bg * 1.5, 0)))
        col_excess = float(np.mean(np.maximum(col_axis - bg * 1.5, 0)))

        score = min((row_excess + col_excess) / (bg + 1e-6) * 0.5, 1.0)
        return score


# ── Utilities ─────────────────────────────────────────────────────────────────

def _block_mean(arr: np.ndarray, block_size: int = 16) -> np.ndarray:
    """Compute mean of non-overlapping blocks."""
    h, w = arr.shape
    bh = (h // block_size) * block_size
    bw = (w // block_size) * block_size
    cropped = arr[:bh, :bw]
    reshaped = cropped.reshape(
        bh // block_size, block_size, bw // block_size, block_size
    )
    return reshaped.mean(axis=(1, 3))


def _save_heatmap(
    heatmap: Optional[np.ndarray],
    path: str | Path,
    title: str,
    cmap: str = "hot",
) -> None:
    """Save a heatmap array as a PNG using matplotlib."""
    if heatmap is None:
        raise ValueError("No heatmap available")
    try:
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8, 8), dpi=100)
        im = ax.imshow(heatmap, cmap=cmap, vmin=0, vmax=1)
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Anomaly score")
        ax.set_title(title, fontsize=12)
        ax.axis("off")
        plt.tight_layout()
        plt.savefig(path, bbox_inches="tight", dpi=150)
        plt.close(fig)
    except ImportError:
        raise ImportError("matplotlib is required to save heatmaps: pip install matplotlib")

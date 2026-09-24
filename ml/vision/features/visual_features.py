"""
PhishGuard AI - Visual Feature Extractor
Extracts interpretable visual telemetry from screenshot images:
- Color distributions & dominant palette
- Edge density (layout structure complexity)
- Whitespace ratio
- Mean luminance & visual contrast
NOTE: These features provide exploratory research telemetry and are not guaranteed phishing proofs.
"""

from typing import Dict, Any, List, Tuple
from pathlib import Path
from PIL import Image, ImageFilter, ImageStat
import numpy as np


class VisualFeatureExtractor:
    @staticmethod
    def extract_features(image_input: Any) -> Dict[str, Any]:
        """
        Extracts high-level visual features from PIL Image or file path.
        """
        if isinstance(image_input, (str, Path)):
            with Image.open(image_input) as img:
                image = img.convert("RGB")
        elif isinstance(image_input, Image.Image):
            image = image_input.convert("RGB")
        else:
            raise ValueError(f"Unsupported image type: {type(image_input)}")

        w, h = image.size
        total_pixels = w * h

        # 1. Luminance & Contrast
        stat = ImageStat.Stat(image)
        mean_r, mean_g, mean_b = stat.mean[:3]
        std_r, std_g, std_b = stat.stddev[:3]
        mean_luminance = (0.299 * mean_r + 0.587 * mean_g + 0.114 * mean_b) / 255.0
        contrast = (0.299 * std_r + 0.587 * std_g + 0.114 * std_b) / 255.0

        # 2. Whitespace ratio (pixels close to white: > 240 in all channels)
        img_np = np.array(image)
        white_pixels = np.sum((img_np[:, :, 0] > 240) & (img_np[:, :, 1] > 240) & (img_np[:, :, 2] > 240))
        whitespace_ratio = float(white_pixels / max(1, total_pixels))

        # 3. Edge density via edge detection
        edges = image.convert("L").filter(ImageFilter.FIND_EDGES)
        edge_np = np.array(edges)
        edge_pixels = np.sum(edge_np > 50)
        edge_density = float(edge_pixels / max(1, total_pixels))

        # 4. Color variance / colorfulness metric (Hasler and Süsstrunk)
        rg = np.absolute(img_np[:, :, 0].astype(float) - img_np[:, :, 1].astype(float))
        yb = np.absolute(0.5 * (img_np[:, :, 0].astype(float) + img_np[:, :, 1].astype(float)) - img_np[:, :, 2].astype(float))
        std_root = np.sqrt(np.var(rg) + np.var(yb))
        mean_root = np.sqrt(np.mean(rg)**2 + np.mean(yb)**2)
        colorfulness = float((std_root + (0.3 * mean_root)) / 100.0)

        # 5. Dominant color approximation
        small = image.resize((50, 50), Image.Resampling.BILINEAR)
        quantized = small.quantize(colors=3)
        palette = quantized.getpalette()[:9]  # 3 RGB colors
        dominant_colors = [
            f"#{palette[i]:02x}{palette[i+1]:02x}{palette[i+2]:02x}"
            for i in range(0, min(len(palette), 9), 3)
        ]

        return {
            "image_width": w,
            "image_height": h,
            "aspect_ratio": round(w / max(1, h), 3),
            "mean_luminance": round(mean_luminance, 4),
            "visual_contrast": round(contrast, 4),
            "whitespace_ratio": round(whitespace_ratio, 4),
            "edge_density": round(edge_density, 4),
            "colorfulness": round(colorfulness, 4),
            "dominant_colors": dominant_colors,
        }

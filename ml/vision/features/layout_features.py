"""
PhishGuard AI - Layout Feature Extractor
Analyzes spatial distribution of webpage elements:
- Top banner / navigation header region complexity
- Central form card localization
- Footer band differentiation
"""

from typing import Dict, Any
from pathlib import Path
from PIL import Image
import numpy as np


class LayoutFeatureExtractor:
    @staticmethod
    def extract_layout_features(image_input: Any) -> Dict[str, Any]:
        """
        Segments webpage screenshot into 3 vertical zones (header: 0-20%, body: 20-80%, footer: 80-100%)
        and evaluates structural complexity and variance across zones.
        """
        if isinstance(image_input, (str, Path)):
            with Image.open(image_input) as img:
                image = img.convert("L")
        elif isinstance(image_input, Image.Image):
            image = image_input.convert("L")
        else:
            raise ValueError(f"Unsupported image type: {type(image_input)}")

        w, h = image.size
        img_np = np.array(image, dtype=float)

        # Slice into zones
        header_h = int(h * 0.20)
        footer_h = int(h * 0.80)

        header_zone = img_np[:header_h, :] if header_h > 0 else img_np
        body_zone = img_np[header_h:footer_h, :] if footer_h > header_h else img_np
        footer_zone = img_np[footer_h:, :] if footer_h < h else img_np

        header_std = float(np.std(header_zone)) / 128.0 if header_zone.size > 0 else 0.0
        body_std = float(np.std(body_zone)) / 128.0 if body_zone.size > 0 else 0.0
        footer_std = float(np.std(footer_zone)) / 128.0 if footer_zone.size > 0 else 0.0

        # Central concentration: evaluate if standard deviation is concentrated in the center 40% of the body (hallmark of single centered login card)
        body_w_mid_start = int(w * 0.30)
        body_w_mid_end = int(w * 0.70)
        center_card = body_zone[:, body_w_mid_start:body_w_mid_end] if body_zone.size > 0 else body_zone
        center_std = float(np.std(center_card)) / 128.0 if center_card.size > 0 else 0.0

        is_centered_card_layout = center_std > 1.3 * (body_std + 1e-5)

        return {
            "header_complexity": round(header_std, 4),
            "body_complexity": round(body_std, 4),
            "footer_complexity": round(footer_std, 4),
            "center_card_complexity": round(center_std, 4),
            "has_centered_card_layout": bool(is_centered_card_layout),
        }

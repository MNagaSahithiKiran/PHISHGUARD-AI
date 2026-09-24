"""
PhishGuard AI - Visual Prediction Service
Production inference service integrating trained vision deep learning models,
Grad-CAM explainability, and structured visual evidence extraction.
"""

import time
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from PIL import Image
try:
    import torch
    from ml.vision.models.model_factory import create_vision_model
    from ml.vision.preprocessing.image_preprocessor import (
        ImagePreprocessor,
        PREPROCESSING_VERSION,
    )
    from ml.vision.features.visual_features import VisualFeatureExtractor
    from ml.vision.features.layout_features import LayoutFeatureExtractor
    from ml.vision.evaluation.explainability import GradCAM
    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    create_vision_model = None
    ImagePreprocessor = None
    PREPROCESSING_VERSION = "0.0.0"
    VisualFeatureExtractor = None
    LayoutFeatureExtractor = None
    GradCAM = None
    TORCH_AVAILABLE = False

from app.vision.visual_evidence_service import generate_visual_evidence

logger = logging.getLogger("phishguard.vision.prediction")

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "ml" / "vision" / "models_artifacts"
SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "screenshots"


class VisualPredictionService:
    _instance: Optional["VisualPredictionService"] = None

    def __init__(self, device: str = "cpu"):
        self.device = device
        self.preprocessor = ImagePreprocessor() if ImagePreprocessor else None
        self.model = None
        self.model_name = "PhishMobileNetV2"
        self.model_version = "1.0.0"
        self.target_layer = None
        if TORCH_AVAILABLE:
            self._load_model()

    @classmethod
    def get_instance(cls) -> "VisualPredictionService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        transfer_ckpt = ARTIFACTS_DIR / "transfer_mobilenet_best.pt"
        baseline_ckpt = ARTIFACTS_DIR / "baseline_cnn_best.pt"

        if transfer_ckpt.exists():
            try:
                self.model = create_vision_model(
                    model_type="transfer",
                    checkpoint_path=transfer_ckpt,
                    device=self.device,
                    pretrained=False,
                )
                self.model_name = "MobileNetV2_Transfer"
                # Target the last inverted residual conv block in MobileNetV2 features
                self.target_layer = self.model.backbone.features[-1]
                logger.info(f"Loaded transfer model from {transfer_ckpt}")
                return
            except Exception as e:
                logger.warning(f"Failed to load transfer model: {e}. Falling back to baseline CNN.")

        if baseline_ckpt.exists():
            try:
                self.model = create_vision_model(
                    model_type="baseline",
                    checkpoint_path=baseline_ckpt,
                    device=self.device,
                    pretrained=False,
                )
                self.model_name = "Baseline_CNN"
                self.target_layer = self.model.block4[0]
                logger.info(f"Loaded baseline CNN model from {baseline_ckpt}")
                return
            except Exception as e:
                logger.error(f"Failed to load baseline CNN: {e}")

        logger.warning("No trained vision checkpoints found. Visual prediction model inactive.")
        self.model = None

    def is_ready(self) -> bool:
        return self.model is not None

    def analyze_image(
        self,
        image_path: Path | str,
        generate_heatmap: bool = True,
        output_heatmap_path: Optional[Path | str] = None,
    ) -> Dict[str, Any]:
        """
        Runs comprehensive visual analysis on an image:
        1. Telemetry extraction (luminance, contrast, whitespace, layout).
        2. Deep learning classification.
        3. Grad-CAM visual explainability heatmap.
        4. Structured security evidence synthesis.
        """
        if not self.is_ready():
            raise RuntimeError("Visual prediction model is not loaded.")

        path = Path(image_path)
        if not path.exists():
            raise FileNotFoundError(f"Image not found at {path}")

        # 1. Feature Telemetry
        with Image.open(path) as img:
            orig_img = img.convert("RGB")
            w, h = orig_img.size

        visual_feat = VisualFeatureExtractor.extract_features(orig_img)
        layout_feat = LayoutFeatureExtractor.extract_layout_features(orig_img)

        # 2. Deep Learning Inference
        input_tensor = self.preprocessor.preprocess_image(orig_img).to(self.device)

        start_time = time.perf_counter()
        with torch.no_grad():
            logits = self.model(input_tensor)
            prob = torch.sigmoid(logits).item()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        pred_label = 1 if prob >= 0.50 else 0
        prediction_str = "phishing" if pred_label == 1 else "legitimate"
        confidence = prob if pred_label == 1 else (1.0 - prob)

        # 3. Grad-CAM Explainability
        heatmap_rel_url = None
        if generate_heatmap and self.target_layer is not None:
            try:
                SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
                if output_heatmap_path:
                    hm_target = Path(output_heatmap_path)
                else:
                    hm_target = SCREENSHOTS_DIR / f"{path.stem}_heatmap.png"

                cam = GradCAM(self.model, self.target_layer)
                # Compute gradients requires enable_grad
                with torch.enable_grad():
                    # Need fresh input tensor requiring grad or standard forward
                    t_eval = self.preprocessor.preprocess_image(orig_img).to(self.device)
                    hm_arr = cam.generate_heatmap(t_eval)
                    blended = cam.overlay_heatmap(orig_img, hm_arr)
                    blended.save(hm_target)
                cam.remove_hooks()

                heatmap_rel_url = f"/api/v1/screenshots/{hm_target.name}"
            except Exception as e:
                logger.warning(f"Grad-CAM generation failed: {e}")

        # 4. Synthesize Evidence
        evidence_items = generate_visual_evidence(
            phishing_probability=prob,
            model_name=self.model_name,
            visual_features=visual_feat,
            layout_features=layout_feat,
        )

        return {
            "status": "completed",
            "prediction": prediction_str,
            "label": pred_label,
            "phishing_probability": round(prob, 4),
            "confidence_score": round(confidence, 4),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "preprocessing_version": PREPROCESSING_VERSION,
            "inference_latency_ms": latency_ms,
            "heatmap_url": heatmap_rel_url,
            "visual_features": {
                "image_width": w,
                "image_height": h,
                "aspect_ratio": round(w / max(1, h), 2),
                "mean_luminance": round(visual_feat.get("mean_luminance", 0.0), 3),
                "visual_contrast": round(visual_feat.get("visual_contrast", 0.0), 3),
                "whitespace_ratio": round(visual_feat.get("whitespace_ratio", 0.0), 3),
                "edge_density": round(visual_feat.get("edge_density", 0.0), 4),
                "colorfulness": round(visual_feat.get("colorfulness", 0.0), 3),
                "dominant_colors": visual_feat.get("dominant_colors", []),
                "has_centered_card": layout_feat.get("has_centered_card_layout", False),
            },
            "evidence": [item.to_dict() for item in evidence_items],
        }

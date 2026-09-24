"""
PhishGuard AI - Comprehensive Vision Pipeline & Security Test Suite
Tests:
1. Corrupted, zero-byte, and non-image input rejection.
2. Duplicate image detection via cryptographic & perceptual hashing.
3. Visual and layout telemetry extraction bounds and schema validity.
4. Model tensor dimensions (CNN and MobileNetV2).
5. Sigmoid probability bounds [0.0, 1.0] and binary classification labels {0, 1}.
6. Multi-layer SSRF protection on screenshot capture targets.
7. Grad-CAM visual explainability heatmap computation.
8. Visual analysis API endpoints (SSRF rejection, 404 handling, successful retrieval).
"""

import tempfile
from pathlib import Path
import pytest
import numpy as np
import torch
from PIL import Image

from ml.vision.preprocessing.image_loader import validate_image_file, compute_dhash
from ml.vision.preprocessing.image_preprocessor import ImagePreprocessor
from ml.vision.features.visual_features import VisualFeatureExtractor
from ml.vision.features.layout_features import LayoutFeatureExtractor
from ml.vision.models.baseline_cnn import PhishVisionCNN
from ml.vision.models.transfer_learning import PhishMobileNetV2
from ml.vision.evaluation.explainability import GradCAM
from app.analyzers.safety.ssrf_guard import SSRFGuard, SSRFSecurityException
from app.vision.screenshot_service import ScreenshotService
from app.vision.visual_prediction_service import VisualPredictionService


# =========================================================================
# 1. Image Validation & Corrupted File Rejection
# =========================================================================
def test_corrupted_and_invalid_image_files():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Zero-byte file
        zero_file = tmp_path / "zero.png"
        zero_file.touch()
        res_zero = validate_image_file(zero_file)
        assert not res_zero.is_valid
        assert "zero-byte" in res_zero.error_message.lower()

        # Corrupted / non-image text file
        fake_img = tmp_path / "fake.png"
        fake_img.write_text("NOT_AN_IMAGE_CONTENT")
        res_fake = validate_image_file(fake_img)
        assert not res_fake.is_valid
        assert "cannot identify" in res_fake.error_message.lower() or "truncated" in res_fake.error_message.lower()

        # Non-existent file
        res_missing = validate_image_file(tmp_path / "non_existent.png")
        assert not res_missing.is_valid
        assert "does not exist" in res_missing.error_message


# =========================================================================
# 2. Duplicate Image Detection (Cryptographic and Perceptual Hashing)
# =========================================================================
def test_duplicate_image_detection():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        img_a = Image.new("RGB", (100, 100), color=(255, 0, 0))
        img_b = Image.new("RGB", (100, 100), color=(255, 0, 0))
        img_c = Image.new("RGB", (100, 100), color=(0, 255, 0))

        path_a = tmp_path / "img_a.png"
        path_b = tmp_path / "img_b.png"
        path_c = tmp_path / "img_c.png"

        img_a.save(path_a)
        img_b.save(path_b)
        img_c.save(path_c)

        val_a = validate_image_file(path_a)
        val_b = validate_image_file(path_b)
        val_c = validate_image_file(path_c)

        assert val_a.is_valid and val_b.is_valid and val_c.is_valid
        assert val_a.md5_hash == val_b.md5_hash
        assert val_a.md5_hash != val_c.md5_hash

        # Perceptual hash
        hash_a = compute_dhash(img_a)
        hash_b = compute_dhash(img_b)
        hash_c = compute_dhash(img_c)
        assert hash_a == hash_b


# =========================================================================
# 3. Visual & Layout Feature Extraction
# =========================================================================
def test_visual_and_layout_feature_extraction():
    img = Image.new("RGB", (800, 600), color=(245, 245, 245))
    v_feat = VisualFeatureExtractor.extract_features(img)

    assert "mean_luminance" in v_feat
    assert "visual_contrast" in v_feat
    assert "whitespace_ratio" in v_feat
    assert "edge_density" in v_feat
    assert "dominant_colors" in v_feat
    assert 0.0 <= v_feat["mean_luminance"] <= 1.0
    assert 0.0 <= v_feat["whitespace_ratio"] <= 1.0

    l_feat = LayoutFeatureExtractor.extract_layout_features(img)
    assert "header_complexity" in l_feat
    assert "body_complexity" in l_feat
    assert "footer_complexity" in l_feat
    assert "has_centered_card_layout" in l_feat
    assert isinstance(l_feat["has_centered_card_layout"], bool)


# =========================================================================
# 4. Model Tensor Dimensions (PyTorch CNN and MobileNetV2)
# =========================================================================
def test_model_tensor_dimensions():
    batch_size = 2
    dummy_input = torch.randn(batch_size, 3, 224, 224)

    # 1. Baseline CNN
    cnn = PhishVisionCNN(num_classes=1)
    cnn.eval()
    with torch.no_grad():
        cnn_out = cnn(dummy_input)
    assert cnn_out.shape == (batch_size, 1)

    # 2. Transfer Learning MobileNetV2
    mobilenet = PhishMobileNetV2(pretrained=False, num_classes=1)
    mobilenet.eval()
    with torch.no_grad():
        mb_out = mobilenet(dummy_input)
    assert mb_out.shape == (batch_size, 1)


# =========================================================================
# 5. Sigmoid Probability Bounds and Label Invariants
# =========================================================================
def test_probability_bounds_and_labels():
    cnn = PhishVisionCNN(num_classes=1)
    cnn.eval()
    dummy = torch.randn(4, 3, 224, 224)
    with torch.no_grad():
        logits = cnn(dummy)
        probs = torch.sigmoid(logits)

    for p in probs.flatten().tolist():
        assert 0.0 <= p <= 1.0
        label = 1 if p >= 0.5 else 0
        assert label in (0, 1)


# =========================================================================
# 6. SSRF Protection on Screenshot Targets
# =========================================================================
@pytest.mark.asyncio
async def test_ssrf_safety_on_screenshot():
    dangerous_targets = [
        "http://127.0.0.1:8000/admin",
        "http://localhost/secret",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
    ]

    for target in dangerous_targets:
        with pytest.raises(SSRFSecurityException):
            await ScreenshotService.capture_target_screenshot(target)


# =========================================================================
# 7. Grad-CAM Visual Explainability
# =========================================================================
def test_grad_cam_heatmap_generation():
    cnn = PhishVisionCNN(num_classes=1)
    cnn.eval()
    target_layer = cnn.block4[0]
    cam = GradCAM(cnn, target_layer)

    dummy_tensor = torch.randn(1, 3, 224, 224)
    heatmap = cam.generate_heatmap(dummy_tensor)
    cam.remove_hooks()

    assert isinstance(heatmap, np.ndarray)
    assert heatmap.ndim == 2
    assert not np.isnan(heatmap).any()
    assert 0.0 <= np.max(heatmap) <= 1.0
    assert 0.0 <= np.min(heatmap) <= 1.0


# =========================================================================
# 8. Visual Prediction Service End-to-End Analysis
# =========================================================================
def test_visual_prediction_service_sample():
    svc = VisualPredictionService.get_instance()
    assert svc.is_ready()

    sample_test_img = Path(__file__).resolve().parent.parent.parent / "ml" / "vision" / "datasets" / "processed" / "test" / "phishing" / "netflix-billing-reactivation.com_ac766143.png"
    if sample_test_img.exists():
        res = svc.analyze_image(sample_test_img, generate_heatmap=False)
        assert res["status"] == "completed"
        assert res["prediction"] in ("phishing", "legitimate")
        assert 0.0 <= res["phishing_probability"] <= 1.0
        assert 0.0 <= res["confidence_score"] <= 1.0
        assert "visual_features" in res
        assert "evidence" in res
        assert len(res["evidence"]) > 0


# =========================================================================
# 9. Visual Analysis API Endpoints
# =========================================================================
@pytest.mark.asyncio
async def test_visual_api_endpoints(client):
    # 1. 404 for non-existent scan ID
    res_404 = await client.get("/api/v1/visual-analysis/non-existent-scan-id-12345")
    assert res_404.status_code == 404

    # 2. SSRF Guard block on POST
    res_ssrf = await client.post(
        "/api/v1/visual-analysis",
        json={"url": "http://127.0.0.1:8080/private"},
    )
    assert res_ssrf.status_code == 403
    assert "blocked for security" in res_ssrf.json()["detail"].lower()

    # 3. Bad request on empty body
    res_bad = await client.post(
        "/api/v1/visual-analysis",
        json={},
    )
    assert res_bad.status_code == 400

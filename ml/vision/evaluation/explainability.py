"""
PhishGuard AI - Grad-CAM Visual Explainability Engine
Generates Gradient-weighted Class Activation Maps (Grad-CAM) to visualize which spatial regions
(e.g., brand logos, fake credential input cards, warning banners) influenced the neural network.
RESEARCH NOTICE: Class activation heatmaps highlight associative visual activations, not causal proof.
"""

from typing import Tuple, Optional, Union
from pathlib import Path
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.vision.preprocessing.image_preprocessor import ImagePreprocessor


class GradCAM:
    def __init__(self, model: nn.Module, target_layer: nn.Module):
        self.model = model
        self.target_layer = target_layer
        self.gradients = None
        self.activations = None
        self.hooks = []
        self._register_hooks()

    def _register_hooks(self):
        def forward_hook(module, input, output):
            self.activations = output.detach()

        def backward_hook(module, grad_input, grad_output):
            self.gradients = grad_output[0].detach()

        self.hooks.append(self.target_layer.register_forward_hook(forward_hook))
        self.hooks.append(self.target_layer.register_full_backward_hook(backward_hook))

    def generate_heatmap(self, input_tensor: torch.Tensor) -> np.ndarray:
        """
        Computes Grad-CAM heatmap normalized to [0, 1].
        input_tensor: shape (1, 3, H, W)
        """
        self.model.zero_grad()
        logits = self.model(input_tensor)

        # Target the single binary logit
        target_score = logits[0, 0]
        target_score.backward()

        # Global average pool the gradients
        # gradients: (1, C, H, W)
        pooled_gradients = torch.mean(self.gradients, dim=[0, 2, 3])  # (C,)

        # Weight the activations by gradients
        activations = self.activations[0]  # (C, H, W)
        for i in range(len(pooled_gradients)):
            activations[i, :, :] *= pooled_gradients[i]

        # Sum across channels and apply ReLU
        heatmap = torch.sum(activations, dim=0).cpu().numpy()
        heatmap = np.maximum(heatmap, 0)

        # Normalize
        if np.max(heatmap) > 0:
            heatmap = heatmap / np.max(heatmap)
        else:
            heatmap = np.zeros_like(heatmap)

        return heatmap

    def overlay_heatmap(
        self,
        original_image: Image.Image,
        heatmap: np.ndarray,
        alpha: float = 0.45,
        colormap_name: str = "jet",
    ) -> Image.Image:
        """
        Overlays normalized heatmap on the original PIL image.
        """
        w, h = original_image.size

        # Resize heatmap to original image dimensions
        heatmap_resized = Image.fromarray((heatmap * 255).astype(np.uint8)).resize(
            (w, h), Image.Resampling.BILINEAR
        )
        heatmap_np = np.array(heatmap_resized) / 255.0

        # Apply colormap
        cmap = cm.get_cmap(colormap_name)
        colored_heatmap = cmap(heatmap_np)[:, :, :3]  # drop alpha channel -> (H, W, 3) in [0, 1]
        colored_heatmap_uint8 = (colored_heatmap * 255).astype(np.uint8)

        # Blend with original
        orig_np = np.array(original_image.convert("RGB"))
        blended = (1.0 - alpha) * orig_np + alpha * colored_heatmap_uint8
        blended_uint8 = np.clip(blended, 0, 255).astype(np.uint8)

        return Image.fromarray(blended_uint8)

    def explain_and_save(
        self,
        image_input: Union[Path, str, Image.Image],
        output_path: Path,
        preprocessor: Optional[ImagePreprocessor] = None,
        device: str = "cpu",
    ) -> Path:
        """
        Runs Grad-CAM and saves overlaid explanation image.
        """
        prep = preprocessor or ImagePreprocessor()

        if isinstance(image_input, (str, Path)):
            with Image.open(image_input) as img:
                orig_img = img.convert("RGB")
        else:
            orig_img = image_input.convert("RGB")

        tensor = prep.preprocess_image(orig_img).to(device)
        heatmap = self.generate_heatmap(tensor)
        blended_img = self.overlay_heatmap(orig_img, heatmap)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        blended_img.save(output_path)
        return output_path

    def remove_hooks(self):
        for hook in self.hooks:
            hook.remove()
        self.hooks = []

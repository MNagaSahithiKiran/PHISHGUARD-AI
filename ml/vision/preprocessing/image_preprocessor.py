"""
PhishGuard AI - Deterministic Image Preprocessing Pipeline
Prepares webpage screenshot images for PyTorch computer vision models:
1. Aspect-ratio preserving resize with letterbox padding.
2. Tensor conversion (C, H, W) in [0.0, 1.0].
3. Normalization using standard ImageNet mean and std.
4. Serialized preprocessing configuration.
"""

from typing import Tuple, Dict, Any, Union
from pathlib import Path
from PIL import Image
import numpy as np
import torch

PREPROCESSING_VERSION = "1.0.0"
DEFAULT_TARGET_SIZE = (224, 224)
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD = [0.229, 0.224, 0.225]


class ImagePreprocessor:
    def __init__(
        self,
        target_size: Tuple[int, int] = DEFAULT_TARGET_SIZE,
        mean: Tuple[float, float, float] = tuple(IMAGENET_MEAN),
        std: Tuple[float, float, float] = tuple(IMAGENET_STD),
        pad_color: Tuple[int, int, int] = (255, 255, 255),
    ):
        self.target_size = target_size
        self.mean = np.array(mean, dtype=np.float32).reshape(3, 1, 1)
        self.std = np.array(std, dtype=np.float32).reshape(3, 1, 1)
        self.pad_color = pad_color
        self.version = PREPROCESSING_VERSION

    def resize_with_padding(self, image: Image.Image) -> Image.Image:
        """
        Resizes PIL image preserving original aspect ratio, centering on a padded canvas.
        Webpage layout proportions (headers, hero banners, login forms) are preserved.
        """
        target_w, target_h = self.target_size
        orig_w, orig_h = image.size

        if orig_w == 0 or orig_h == 0:
            return Image.new("RGB", self.target_size, self.pad_color)

        scale = min(target_w / orig_w, target_h / orig_h)
        new_w = max(1, int(orig_w * scale))
        new_h = max(1, int(orig_h * scale))

        resized = image.resize((new_w, new_h), Image.Resampling.BILINEAR)

        padded = Image.new("RGB", self.target_size, self.pad_color)
        paste_x = (target_w - new_w) // 2
        paste_y = (target_h - new_h) // 2
        padded.paste(resized, (paste_x, paste_y))

        return padded

    def transform_pil_to_tensor(self, image: Image.Image) -> torch.Tensor:
        """
        Transforms a PIL image to a normalized PyTorch tensor of shape (3, H, W).
        """
        if image.mode != "RGB":
            image = image.convert("RGB")

        padded_img = self.resize_with_padding(image)
        img_np = np.array(padded_img, dtype=np.float32) / 255.0  # (H, W, 3)

        # Transpose to (3, H, W)
        tensor_np = np.transpose(img_np, (2, 0, 1))

        # Normalize
        norm_tensor = (tensor_np - self.mean) / self.std

        return torch.from_numpy(norm_tensor.copy()).float()

    def preprocess_image(self, image_input: Union[Path, str, Image.Image]) -> torch.Tensor:
        """
        End-to-end preprocessing returning a batched tensor (1, 3, H, W).
        """
        if isinstance(image_input, (str, Path)):
            path = Path(image_input)
            with Image.open(path) as img:
                pil_img = img.convert("RGB")
                tensor = self.transform_pil_to_tensor(pil_img)
        elif isinstance(image_input, Image.Image):
            tensor = self.transform_pil_to_tensor(image_input)
        else:
            raise ValueError(f"Unsupported image input type: {type(image_input)}")

        return tensor.unsqueeze(0)  # Add batch dimension -> (1, 3, H, W)

    def get_config(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "target_size": list(self.target_size),
            "mean": [float(m) for m in self.mean.flatten()],
            "std": [float(s) for s in self.std.flatten()],
            "pad_color": list(self.pad_color),
            "aspect_ratio_mode": "preserve_with_letterbox_padding",
        }

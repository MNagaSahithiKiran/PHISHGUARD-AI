"""
PhishGuard AI - PyTorch Dataset for Webpage Screenshots
Loads images from structured class directories (legitimate / phishing) for train/val/test splits.
Enforces that augmentations are applied strictly to the training split.
"""

from typing import List, Tuple, Dict, Any, Optional
from pathlib import Path
from PIL import Image
import torch
from torch.utils.data import Dataset

from ml.vision.preprocessing.image_loader import load_image_rgb
from ml.vision.preprocessing.image_preprocessor import ImagePreprocessor
from ml.vision.preprocessing.augmentation import TrainingAugmentor


class WebpageScreenshotDataset(Dataset):
    def __init__(
        self,
        split_dir: Path,
        split_name: str = "train",
        preprocessor: Optional[ImagePreprocessor] = None,
        augmentor: Optional[TrainingAugmentor] = None,
    ):
        self.split_dir = Path(split_dir)
        self.split_name = split_name.lower()
        self.preprocessor = preprocessor or ImagePreprocessor()
        # Strictly apply augmentor ONLY if split is train
        self.augmentor = augmentor if self.split_name == "train" else None

        self.samples: List[Tuple[Path, float, str]] = []
        self._load_samples()

    def _load_samples(self):
        legit_dir = self.split_dir / "legitimate"
        phish_dir = self.split_dir / "phishing"

        if legit_dir.exists():
            for p in sorted(legit_dir.glob("*.png")):
                self.samples.append((p, 0.0, "legitimate"))
            for p in sorted(legit_dir.glob("*.jpg")):
                self.samples.append((p, 0.0, "legitimate"))

        if phish_dir.exists():
            for p in sorted(phish_dir.glob("*.png")):
                self.samples.append((p, 1.0, "phishing"))
            for p in sorted(phish_dir.glob("*.jpg")):
                self.samples.append((p, 1.0, "phishing"))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, str]:
        img_path, label_float, class_name = self.samples[idx]

        # Load RGB image safely
        img = load_image_rgb(img_path)

        # Apply augmentation only if train
        if self.augmentor is not None:
            img = self.augmentor(img)

        # Transform to normalized tensor (3, 224, 224)
        tensor = self.preprocessor.transform_pil_to_tensor(img)
        label_tensor = torch.tensor([label_float], dtype=torch.float32)

        return tensor, label_tensor, str(img_path)

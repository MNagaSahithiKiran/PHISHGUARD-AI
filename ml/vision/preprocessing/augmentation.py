"""
PhishGuard AI - Data Augmentation Pipeline
Applies subtle, realistic geometric and photometric augmentations for training data.
CRITICAL CONSTRAINT: Augmentation is NEVER applied to validation or test data.
Transformations preserve realistic webpage structure without distortion.
"""

import random
from PIL import Image, ImageEnhance


class TrainingAugmentor:
    """
    Subtle augmentations suitable for webpage screenshots:
    - Small brightness adjustment (±10%)
    - Small contrast adjustment (±10%)
    - Micro horizontal/vertical shift (±2%)
    - Micro rotation (±2 degrees)
    """
    def __init__(
        self,
        brightness_range: float = 0.10,
        contrast_range: float = 0.10,
        rotation_degrees: float = 2.0,
        translation_percent: float = 0.02,
    ):
        self.brightness_range = brightness_range
        self.contrast_range = contrast_range
        self.rotation_degrees = rotation_degrees
        self.translation_percent = translation_percent

    def __call__(self, image: Image.Image) -> Image.Image:
        img = image.copy()

        # 1. Subtle brightness
        if self.brightness_range > 0:
            factor = 1.0 + random.uniform(-self.brightness_range, self.brightness_range)
            enhancer = ImageEnhance.Brightness(img)
            img = enhancer.enhance(factor)

        # 2. Subtle contrast
        if self.contrast_range > 0:
            factor = 1.0 + random.uniform(-self.contrast_range, self.contrast_range)
            enhancer = ImageEnhance.Contrast(img)
            img = enhancer.enhance(factor)

        # 3. Micro-rotation (fill with white canvas background)
        if self.rotation_degrees > 0:
            angle = random.uniform(-self.rotation_degrees, self.rotation_degrees)
            img = img.rotate(angle, resample=Image.Resampling.BILINEAR, expand=False, fillcolor=(255, 255, 255))

        # 4. Micro-translation
        if self.translation_percent > 0:
            w, h = img.size
            max_dx = int(w * self.translation_percent)
            max_dy = int(h * self.translation_percent)
            dx = random.randint(-max_dx, max_dx)
            dy = random.randint(-max_dy, max_dy)
            
            translated = Image.new("RGB", (w, h), (255, 255, 255))
            translated.paste(img, (dx, dy))
            img = translated

        return img

"""
PhishGuard AI - Image Loader & Quality Validation
Validates, checks corruption, filters 0-byte files, converts color modes to RGB,
and computes cryptographic and perceptual hashes for duplicate detection.
"""

import os
import hashlib
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path
from PIL import Image, ImageOps


class ImageValidationResult:
    def __init__(
        self,
        is_valid: bool,
        error_message: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        channels: int = 0,
        format_name: str = "",
        md5_hash: str = "",
    ):
        self.is_valid = is_valid
        self.error_message = error_message
        self.width = width
        self.height = height
        self.channels = channels
        self.format_name = format_name
        self.md5_hash = md5_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "error_message": self.error_message,
            "width": self.width,
            "height": self.height,
            "channels": self.channels,
            "format": self.format_name,
            "md5": self.md5_hash,
        }


def compute_file_md5(file_path: Path) -> str:
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_dhash(image: Image.Image, hash_size: int = 8) -> int:
    """
    Computes difference hash (dHash) for near-duplicate screenshot detection.
    """
    resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.BILINEAR)
    diff = []
    for row in range(hash_size):
        for col in range(hash_size):
            pixel_left = resized.getpixel((col, row))
            pixel_right = resized.getpixel((col + 1, row))
            diff.append(pixel_left > pixel_right)
    decimal_value = 0
    for index, value in enumerate(diff):
        if value:
            decimal_value += 2 ** index
    return decimal_value


def validate_image_file(file_path: Path) -> ImageValidationResult:
    """
    Performs thorough integrity validation on an image file.
    """
    if not file_path.exists():
        return ImageValidationResult(False, "File does not exist.")

    file_size = file_path.stat().st_size
    if file_size == 0:
        return ImageValidationResult(False, "Zero-byte image file.")

    if file_size > 25 * 1024 * 1024:
        return ImageValidationResult(False, "File exceeds maximum screenshot size (25MB).")

    try:
        md5 = compute_file_md5(file_path)
        with Image.open(file_path) as img:
            img.verify()

        # Reopen to read dimensions and mode (verify closes file descriptor)
        with Image.open(file_path) as img:
            width, height = img.size
            if width < 32 or height < 32:
                return ImageValidationResult(False, f"Image dimensions too small ({width}x{height}).")

            fmt = img.format or "UNKNOWN"
            channels = len(img.getbands())

            return ImageValidationResult(
                is_valid=True,
                width=width,
                height=height,
                channels=channels,
                format_name=fmt,
                md5_hash=md5,
            )

    except Exception as e:
        return ImageValidationResult(False, f"Corrupted or invalid image: {str(e)}")


def load_image_rgb(file_path: Path) -> Image.Image:
    """
    Loads image and standardizes into 3-channel RGB.
    Handles RGBA, Palette (P), Grayscale (L), and CMYK cleanly.
    """
    with Image.open(file_path) as img:
        # Correct EXIF orientation if present
        img = ImageOps.exif_transpose(img)
        if img.mode != "RGB":
            img = img.convert("RGB")
        return img.copy()

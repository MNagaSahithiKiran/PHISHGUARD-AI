"""
PhishGuard AI - Vision Model Factory
Instantiates and loads vision models with serialized checkpoint weights.
"""

from typing import Optional, Union
from pathlib import Path
import torch
import torch.nn as nn

from ml.vision.models.baseline_cnn import PhishVisionCNN
from ml.vision.models.transfer_learning import PhishMobileNetV2


def create_vision_model(
    model_type: str = "transfer",
    checkpoint_path: Optional[Union[str, Path]] = None,
    device: str = "cpu",
    pretrained: bool = True,
) -> nn.Module:
    """
    Factory function to instantiate vision models.
    model_type: 'baseline' (PhishVisionCNN) or 'transfer' (PhishMobileNetV2)
    """
    if model_type.lower() in ("baseline", "cnn", "phishvisioncnn"):
        model = PhishVisionCNN(num_classes=1)
    elif model_type.lower() in ("transfer", "mobilenet", "mobilenetv2", "phishmobilenetv2"):
        model = PhishMobileNetV2(pretrained=pretrained, num_classes=1)
    else:
        raise ValueError(f"Unknown model type: {model_type}. Expected 'baseline' or 'transfer'.")

    if checkpoint_path is not None:
        path = Path(checkpoint_path)
        if path.exists():
            state_dict = torch.load(path, map_location=device, weights_only=True)
            if "model_state_dict" in state_dict:
                model.load_state_dict(state_dict["model_state_dict"])
            elif "state_dict" in state_dict:
                model.load_state_dict(state_dict["state_dict"])
            else:
                model.load_state_dict(state_dict)

    model.to(device)
    model.eval()
    return model

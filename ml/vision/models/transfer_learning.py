"""
PhishGuard AI - Transfer Learning Architecture (MobileNetV2)
Leverages ImageNet visual feature representations with frozen/fine-tuned inverted residuals
and a custom classification head for webpage screenshot phishing detection.
"""

from typing import Dict, Any, Optional
import torch
import torch.nn as nn
from torchvision.models import mobilenet_v2, MobileNet_V2_Weights


class PhishMobileNetV2(nn.Module):
    def __init__(
        self,
        pretrained: bool = True,
        freeze_backbone_blocks: int = 14,
        num_classes: int = 1,
        dropout_rate: float = 0.3,
    ):
        super().__init__()
        self.num_classes = num_classes

        # Load MobileNetV2 backbone
        try:
            if pretrained:
                weights = MobileNet_V2_Weights.DEFAULT
                self.backbone = mobilenet_v2(weights=weights)
            else:
                self.backbone = mobilenet_v2(weights=None)
        except Exception:
            # Fallback if offline / cache missing
            self.backbone = mobilenet_v2(weights=None)

        # Freeze early feature extraction layers
        if freeze_backbone_blocks > 0:
            for idx, child in enumerate(self.backbone.features):
                if idx < freeze_backbone_blocks:
                    for param in child.parameters():
                        param.requires_grad = False

        # Replace classification head
        in_features = self.backbone.classifier[1].in_features  # 1280
        self.backbone.classifier = nn.Sequential(
            nn.Dropout(p=dropout_rate),
            nn.Linear(in_features, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(p=dropout_rate * 0.5),
            nn.Linear(128, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.backbone(x)

    def get_target_conv_layer(self) -> nn.Module:
        """
        Returns the final convolutional feature layer for Grad-CAM.
        """
        return self.backbone.features[-1]

    def count_parameters(self) -> Dict[str, int]:
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        total = sum(p.numel() for p in self.parameters())
        return {
            "total_parameters": total,
            "trainable_parameters": trainable,
            "frozen_parameters": total - trainable,
        }

    def get_model_info(self) -> Dict[str, Any]:
        param_info = self.count_parameters()
        return {
            "model_name": "PhishMobileNetV2",
            "base_architecture": "MobileNetV2 (ImageNet)",
            "total_parameters": param_info["total_parameters"],
            "trainable_parameters": param_info["trainable_parameters"],
            "frozen_parameters": param_info["frozen_parameters"],
            "num_classes": self.num_classes,
        }

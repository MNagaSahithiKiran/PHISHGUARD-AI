"""
PhishGuard AI - Baseline Webpage Vision CNN
A purpose-built convolutional neural network architecture for binary classification
of webpage screenshots (0: Legitimate, 1: Phishing).
"""

from typing import Dict, Any
import torch
import torch.nn as nn


class PhishVisionCNN(nn.Module):
    def __init__(self, num_classes: int = 1, dropout_rate: float = 0.4):
        super().__init__()
        self.num_classes = num_classes

        # Block 1: 3 -> 32 (224x224 -> 112x112)
        self.block1 = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),
        )

        # Block 2: 32 -> 64 (112x112 -> 56x56)
        self.block2 = nn.Sequential(
            nn.Conv2d(32, 64, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),
        )

        # Block 3: 64 -> 128 (56x56 -> 28x28)
        self.block3 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),
        )

        # Block 4: 128 -> 256 (28x28 -> 14x14)
        self.block4 = nn.Sequential(
            nn.Conv2d(128, 256, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(256),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),
        )

        self.global_pool = nn.AdaptiveAvgPool2d((1, 1))

        self.classifier = nn.Sequential(
            nn.Dropout(p=dropout_rate),
            nn.Linear(256, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(p=dropout_rate * 0.5),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.block1(x)
        x = self.block2(x)
        x = self.block3(x)
        x = self.block4(x)
        x = self.global_pool(x)
        x = torch.flatten(x, 1)
        logits = self.classifier(x)
        return logits

    def get_target_conv_layer(self) -> nn.Module:
        """
        Returns the final convolutional layer for Grad-CAM visual explainability.
        """
        return self.block4[0]

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "model_name": "PhishVisionCNN",
            "architecture": "4-Block Custom CNN",
            "parameters": self.count_parameters(),
            "input_shape": [3, 224, 224],
            "num_classes": self.num_classes,
        }

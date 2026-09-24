"""
PhishGuard AI - Transfer Learning Vision Training Pipeline (MobileNetV2)
Fine-tunes pretrained ImageNet representations for webpage screenshot classification.
Implements frozen backbone blocks, validation tracking, checkpointing, and history persistence.
"""

import os
import sys
import json
import time
from pathlib import Path
import yaml
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import f1_score, accuracy_score

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.vision.models.transfer_learning import PhishMobileNetV2
from ml.vision.training.dataset import WebpageScreenshotDataset
from ml.vision.preprocessing.image_preprocessor import ImagePreprocessor
from ml.vision.preprocessing.augmentation import TrainingAugmentor

CONFIG_PATH = Path(__file__).resolve().parent / "training_config.yaml"
ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "models_artifacts"
EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent / "experiments"
DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"


def train_transfer_learning():
    # 1. Load Configuration
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    seed = config.get("seed", 42)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[Training] Using compute device: {device}")

    # 2. Setup Data
    preprocessor = ImagePreprocessor()
    aug_cfg = config.get("augmentation", {})
    augmentor = TrainingAugmentor(
        brightness_range=aug_cfg.get("brightness_range", 0.10),
        contrast_range=aug_cfg.get("contrast_range", 0.10),
        rotation_degrees=aug_cfg.get("rotation_degrees", 2.0),
        translation_percent=aug_cfg.get("translation_percent", 0.02),
    )

    train_dataset = WebpageScreenshotDataset(
        split_dir=DATASET_DIR / "train",
        split_name="train",
        preprocessor=preprocessor,
        augmentor=augmentor,
    )
    val_dataset = WebpageScreenshotDataset(
        split_dir=DATASET_DIR / "val",
        split_name="val",
        preprocessor=preprocessor,
        augmentor=None,
    )

    batch_size = config.get("batch_size", 8)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    print(f"[Dataset] Train samples: {len(train_dataset)} | Validation samples: {len(val_dataset)}")

    # 3. Model & Optimizer
    transfer_cfg = config.get("transfer_learning", {})
    freeze_blocks = transfer_cfg.get("freeze_backbone_blocks", 14)
    model = PhishMobileNetV2(
        pretrained=True,
        freeze_backbone_blocks=freeze_blocks,
        num_classes=1,
        dropout_rate=transfer_cfg.get("dropout_rate", 0.3),
    )
    model.to(device)

    # Train only parameters that require grad
    trainable_params = [p for p in model.parameters() if p.requires_grad]
    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(
        trainable_params,
        lr=float(transfer_cfg.get("learning_rate", 0.0003)),
        weight_decay=float(transfer_cfg.get("weight_decay", 1e-4)),
    )

    epochs = transfer_cfg.get("epochs", 12)
    best_val_f1 = -1.0
    best_epoch = 0
    history = {"train_loss": [], "val_loss": [], "val_accuracy": [], "val_f1": []}

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
    best_model_path = ARTIFACTS_DIR / "transfer_mobilenet_best.pt"

    start_train_time = time.time()

    # 4. Training Loop
    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0

        for tensors, labels, _ in train_loader:
            tensors, labels = tensors.to(device), labels.to(device)
            optimizer.zero_grad()
            logits = model(tensors)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * tensors.size(0)

        epoch_train_loss = running_loss / max(1, len(train_dataset))

        # Validation
        model.eval()
        val_loss = 0.0
        val_preds = []
        val_targets = []

        with torch.no_grad():
            for tensors, labels, _ in val_loader:
                tensors, labels = tensors.to(device), labels.to(device)
                logits = model(tensors)
                loss = criterion(logits, labels)
                val_loss += loss.item() * tensors.size(0)
                probs = torch.sigmoid(logits)
                preds = (probs >= 0.5).int()
                val_preds.extend(preds.cpu().numpy().flatten().tolist())
                val_targets.extend(labels.cpu().numpy().flatten().astype(int).tolist())

        epoch_val_loss = val_loss / max(1, len(val_dataset))
        val_acc = accuracy_score(val_targets, val_preds) if val_targets else 0.0
        val_f1 = f1_score(val_targets, val_preds, zero_division=0) if val_targets else 0.0

        history["train_loss"].append(round(epoch_train_loss, 4))
        history["val_loss"].append(round(epoch_val_loss, 4))
        history["val_accuracy"].append(round(val_acc, 4))
        history["val_f1"].append(round(val_f1, 4))

        print(f"Epoch {epoch:02d}/{epochs:02d} - Train Loss: {epoch_train_loss:.4f} | Val Loss: {epoch_val_loss:.4f} | Val Acc: {val_acc:.4f} | Val F1: {val_f1:.4f}")

        # Checkpoint best model
        if val_f1 >= best_val_f1:
            best_val_f1 = val_f1
            best_epoch = epoch
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_f1": val_f1,
                    "val_acc": val_acc,
                    "config": config,
                    "model_name": "PhishMobileNetV2",
                },
                best_model_path,
            )

    total_time = round(time.time() - start_train_time, 2)
    print(f"\n[MobileNetV2] Training complete in {total_time}s. Best Epoch: {best_epoch} (Val F1: {best_val_f1:.4f})")
    print(f"[Artifact] Saved best weights to: {best_model_path}")

    # Save history
    history_path = EXPERIMENTS_DIR / "history_transfer_mobilenet.json"
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "model_name": "PhishMobileNetV2",
                "training_time_seconds": total_time,
                "best_epoch": best_epoch,
                "best_val_f1": best_val_f1,
                "history": history,
            },
            f,
            indent=2,
        )

    return str(best_model_path)


if __name__ == "__main__":
    train_transfer_learning()

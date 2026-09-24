"""
PhishGuard AI - Multi-Modal Fusion Model Training Pipeline
Trains:
1. Probability-level weighted fusion (Strategy A)
2. Stacking meta-classifier with fallback sub-models (Strategy B)
3. Evidence-enhanced meta-classifier (Strategy C)
Fits probability calibration (Platt scaling / Isotonic) and decision thresholds on validation data.
Saves all production artifacts to ml/fusion/artifacts/.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import yaml

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.fusion.models.simple_fusion import SimpleProbabilityFusion
from ml.fusion.models.stacking_model import StackingFusionModel
from ml.fusion.models.meta_classifier import EvidenceEnhancedFusionModel, EVIDENCE_FEATURE_NAMES
from ml.fusion.models.fusion_factory import save_fusion_model
from ml.fusion.calibration.probability_calibration import ProbabilityCalibrator, compute_brier_score
from ml.fusion.calibration.threshold_selection import select_optimal_thresholds

DATASETS_DIR = REPO_ROOT / "ml" / "fusion" / "datasets"
ARTIFACTS_DIR = REPO_ROOT / "ml" / "fusion" / "artifacts"
CONFIG_PATH = REPO_ROOT / "ml" / "fusion" / "training" / "config.yaml"


def train_fusion_pipeline():
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    print("============================================================")
    print("PHISHGUARD AI - MULTI-MODAL FUSION TRAINING PIPELINE")
    print("============================================================")

    # 1. Load Data
    train_path = DATASETS_DIR / "train.csv"
    val_path = DATASETS_DIR / "val.csv"

    if not train_path.exists() or not val_path.exists():
        raise FileNotFoundError("Train or Val split not found. Run build_fusion_dataset.py first.")

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    print(f"Loaded {len(train_df)} training samples and {len(val_df)} validation samples.")

    # Base probability matrices
    X_train_probs = train_df[["p_url", "p_website", "p_visual"]].values
    y_train = train_df["label"].values

    X_val_probs = val_df[["p_url", "p_website", "p_visual"]].values
    y_val = val_df["label"].values

    # 2. Train Strategy A: Simple Probability Fusion
    print("\n[Strategy A] Fitting validation-optimized Probability-Level Weighted Fusion...")
    simple_fusion = SimpleProbabilityFusion(method="weighted")
    opt_weights = simple_fusion.fit_weights(X_val_probs, y_val)
    print(f"  Learned Empirical Weights: URL={opt_weights[0]:.4f}, Website={opt_weights[1]:.4f}, Visual={opt_weights[2]:.4f}")
    save_fusion_model(simple_fusion, ARTIFACTS_DIR / "simple_fusion_best.joblib")

    # 3. Train Strategy B: Stacking Meta-Classifier
    print("\n[Strategy B] Fitting Stacking Meta-Classifier with dynamic fallback sub-models...")
    stacking_model = StackingFusionModel(C=1.0, random_state=42)
    stacking_model.fit(X_train_probs, y_train)
    coefs = stacking_model.get_coefficients()
    print(f"  Learned Stacking Coefficients: {coefs}")
    save_fusion_model(stacking_model, ARTIFACTS_DIR / "stacking_fusion_best.joblib")

    # 4. Train Strategy C: Evidence-Enhanced Meta-Classifier
    print("\n[Strategy C] Fitting Evidence-Enhanced Meta-Classifier...")
    X_train_ev = train_df[EVIDENCE_FEATURE_NAMES].values
    evidence_model = EvidenceEnhancedFusionModel(C=0.5, random_state=42)
    evidence_model.fit(X_train_ev, y_train)
    top_effects = evidence_model.get_feature_importances()[:4]
    print(f"  Top Evidence Impact Features: {top_effects}")
    save_fusion_model(evidence_model, ARTIFACTS_DIR / "evidence_fusion_best.joblib")

    # 5. Fit Probability Calibrators on Validation Set
    print("\n[Calibration] Fitting Platt scaling calibrator on validation probabilities...")
    # Generate uncalibrated stacking probabilities on validation set
    val_raw_probs = np.array([
        stacking_model.predict_probability(row[0], row[1], row[2])[0]
        for row in X_val_probs
    ])
    raw_brier = compute_brier_score(val_raw_probs, y_val)

    calibrator = ProbabilityCalibrator(method="platt")
    calibrator.fit(val_raw_probs, y_val)
    cal_val_probs = calibrator.calibrate_array(val_raw_probs)
    cal_brier = compute_brier_score(cal_val_probs, y_val)

    print(f"  Validation Brier Score: Raw={raw_brier:.4f} -> Calibrated={cal_brier:.4f}")
    calibrator.save(ARTIFACTS_DIR / "probability_calibrator_best.joblib")

    # 6. Select Empirical Decision Policy Thresholds
    print("\n[Decision Policy] Selecting empirical decision boundaries on validation data...")
    policy = select_optimal_thresholds(val_probs=cal_val_probs, val_labels=y_val)
    policy_path = ARTIFACTS_DIR / "decision_policy.json"
    policy.save(policy_path)
    print(f"  Legitimate Upper Threshold: <= {policy.legitimate_upper_threshold}")
    print(f"  Phishing Lower Threshold:   >= {policy.phishing_lower_threshold}")
    print(f"  Suspicious Ambiguity Band:  ({policy.legitimate_upper_threshold}, {policy.phishing_lower_threshold})")
    print(f"[Artifact] Saved decision policy to: {policy_path}")

    print("\nMulti-modal fusion training & calibration complete!")


if __name__ == "__main__":
    train_fusion_pipeline()

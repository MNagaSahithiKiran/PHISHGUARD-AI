"""
PhishGuard AI - Unified Feature Pipeline.
Ensures zero training-serving skew by maintaining identical feature extraction,
ordering, and preprocessing transformations for both offline training and live API inference.
"""

import json
from pathlib import Path
from typing import List, Dict, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

from ml.feature_engineering.url_features import extract_url_feature_vector

SCHEMA_PATH = Path(__file__).resolve().parent / "feature_schema.json"
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.joblib"


def get_feature_names() -> List[str]:
    """Retrieves canonical deterministic ordered feature names from the versioned schema."""
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return [item["name"] for item in schema["features"]]


FEATURE_NAMES = get_feature_names()


class FeaturePipeline:
    def __init__(self, scaler: StandardScaler = None):
        self.feature_names = FEATURE_NAMES
        self.scaler = scaler or StandardScaler()
        self.is_fitted = False

    def extract_dict(self, url: str) -> Dict[str, Union[int, float]]:
        """Extracts features for a single URL string."""
        raw_feats = extract_url_feature_vector(url)
        # Ensure exact schema ordering
        return {name: raw_feats.get(name, 0.0) for name in self.feature_names}

    def extract_df(self, urls: List[str]) -> pd.DataFrame:
        """Extracts feature matrix DataFrame for an iterable of URLs."""
        rows = [self.extract_dict(u) for u in urls]
        return pd.DataFrame(rows, columns=self.feature_names)

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """Fits scaler on training DataFrame and transforms it."""
        X_ordered = X[self.feature_names].values
        scaled = self.scaler.fit_transform(X_ordered)
        self.is_fitted = True
        return scaled

    def transform(self, X: Union[pd.DataFrame, List[Dict[str, Union[int, float]]], np.ndarray]) -> np.ndarray:
        """Transforms feature matrix using fitted scaler without refitting."""
        if isinstance(X, pd.DataFrame):
            X_arr = X[self.feature_names].values
        elif isinstance(X, list) and isinstance(X[0], dict):
            X_arr = np.array([[row.get(name, 0.0) for name in self.feature_names] for row in X])
        elif isinstance(X, np.ndarray):
            X_arr = X
        else:
            raise TypeError("Unsupported feature input type")

        if self.is_fitted:
            return self.scaler.transform(X_arr)
        return X_arr

    def save(self, filepath: Path = DEFAULT_PREPROCESSOR_PATH):
        """Serializes preprocessor state."""
        joblib.dump({
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "is_fitted": self.is_fitted,
            "version": "2.0.0"
        }, filepath)

    @classmethod
    def load(cls, filepath: Path = DEFAULT_PREPROCESSOR_PATH) -> "FeaturePipeline":
        """Loads preprocessor state from serialized checkpoint."""
        if not Path(filepath).exists():
            raise FileNotFoundError(f"Preprocessor checkpoint not found at {filepath}")
        data = joblib.load(filepath)
        instance = cls(scaler=data["scaler"])
        instance.feature_names = data["feature_names"]
        instance.is_fitted = data["is_fitted"]
        return instance

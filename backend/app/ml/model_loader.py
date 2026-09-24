import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import joblib
from app.core.logging import logger

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MODELS_DIR = REPO_ROOT / "ml" / "models"
METADATA_PATH = MODELS_DIR / "model_metadata.json"
PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.joblib"


class ModelLoader:
    _instance: Optional["ModelLoader"] = None

    def __init__(self):
        self.metadata: Optional[Dict[str, Any]] = None
        self.model = None
        self.preprocessor = None
        self.is_loaded = False
        self._load()

    def _load(self):
        if not METADATA_PATH.exists() or not PREPROCESSOR_PATH.exists():
            self.is_loaded = False
            return

        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

            model_filename = self.metadata.get("model_file", "random_forest.joblib")
            model_path = MODELS_DIR / model_filename

            if not model_path.exists():
                self.is_loaded = False
                return

            import hashlib

            def compute_file_hash(filepath: Path) -> str:
                h = hashlib.sha256()
                with open(filepath, "rb") as f_obj:
                    while chunk := f_obj.read(65536):
                        h.update(chunk)
                return h.hexdigest()

            self.model_hash = compute_file_hash(model_path)
            self.preprocessor_hash = compute_file_hash(PREPROCESSOR_PATH)

            expected_model_hash = self.metadata.get("model_sha256")
            expected_prep_hash = self.metadata.get("preprocessor_sha256")

            if expected_model_hash and self.model_hash.lower() != expected_model_hash.lower():
                raise ValueError(
                    f"ML Model Artifact Hash Mismatch! Expected {expected_model_hash}, computed {self.model_hash}. Potential tampering or corruption detected."
                )

            if expected_prep_hash and self.preprocessor_hash.lower() != expected_prep_hash.lower():
                raise ValueError(
                    f"Preprocessor Artifact Hash Mismatch! Expected {expected_prep_hash}, computed {self.preprocessor_hash}. Potential tampering or corruption detected."
                )

            self.model = joblib.load(model_path)
            
            # Load FeaturePipeline preprocessor
            from ml.feature_engineering.feature_pipeline import FeaturePipeline
            self.preprocessor = FeaturePipeline.load(PREPROCESSOR_PATH)
            self.is_loaded = True
            logger.info(f"Loaded and verified ML model '{model_filename}' (SHA-256: {self.model_hash[:16]}...)")
        except Exception as e:
            logger.error(f"Error loading ML model artifacts: {e}")
            self.is_loaded = False

    def reload(self):
        self._load()

    @classmethod
    def get_instance(cls) -> "ModelLoader":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


model_loader = ModelLoader.get_instance()

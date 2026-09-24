from typing import Dict, Union
from app.ml.model_loader import model_loader
from ml.feature_engineering.feature_pipeline import FeaturePipeline


class FeatureService:
    @staticmethod
    def extract_features(url: str) -> Dict[str, Union[int, float]]:
        """
        Extracts 34 deterministic features for the given URL using the
        versioned schema pipeline.
        """
        if model_loader.preprocessor is not None:
            return model_loader.preprocessor.extract_dict(url)
        # Fallback to fresh pipeline if loader is not initialized
        pipeline = FeaturePipeline()
        return pipeline.extract_dict(url)

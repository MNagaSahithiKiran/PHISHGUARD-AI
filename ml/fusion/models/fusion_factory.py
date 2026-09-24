"""
PhishGuard AI - Multi-Modal Fusion Model Factory
Instantiates, serializes, and deserializes multimodal fusion models.
"""

from typing import Union, Optional
from pathlib import Path
import joblib

from ml.fusion.models.simple_fusion import SimpleProbabilityFusion
from ml.fusion.models.stacking_model import StackingFusionModel
from ml.fusion.models.meta_classifier import EvidenceEnhancedFusionModel


FusionModelType = Union[SimpleProbabilityFusion, StackingFusionModel, EvidenceEnhancedFusionModel]


def create_fusion_model(
    model_type: str = "stacking",
    checkpoint_path: Optional[Union[str, Path]] = None,
    **kwargs
) -> FusionModelType:
    """
    Factory function for fusion models:
    - 'simple': SimpleProbabilityFusion
    - 'stacking': StackingFusionModel
    - 'evidence_enhanced': EvidenceEnhancedFusionModel
    """
    m_type = model_type.lower()
    if checkpoint_path is not None:
        path = Path(checkpoint_path)
        if path.exists():
            return joblib.load(path)

    if m_type in ("simple", "mean", "probability"):
        return SimpleProbabilityFusion(method=kwargs.get("method", "mean"))
    elif m_type in ("stacking", "meta"):
        return StackingFusionModel(C=kwargs.get("C", 1.0), random_state=kwargs.get("random_state", 42))
    elif m_type in ("evidence", "evidence_enhanced"):
        return EvidenceEnhancedFusionModel(C=kwargs.get("C", 0.5), random_state=kwargs.get("random_state", 42))
    else:
        raise ValueError(f"Unknown fusion model type: {model_type}")


def save_fusion_model(model: FusionModelType, output_path: Union[str, Path]):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    return path

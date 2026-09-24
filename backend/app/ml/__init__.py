# ML Module initialization - Honest state representation
class MLModelRegistry:
    """
    Registry for PhishGuard AI models.
    Will hold loaded weights once datasets are acquired and trained.
    Currently indicates that models are not trained yet.
    """
    is_trained: bool = False
    model_version: str = "none"

    @classmethod
    def get_status(cls) -> dict:
        return {
            "is_trained": cls.is_trained,
            "model_version": cls.model_version,
            "message": "Model weights pending real dataset training pipeline execution."
        }

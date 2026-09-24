import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
from ml.feature_engineering.feature_pipeline import FeaturePipeline
from ml.evaluation.explainability import ExplainabilityEngine

pipeline = FeaturePipeline.load()
model = joblib.load(REPO_ROOT / "ml" / "models" / "random_forest.joblib")
explainer = ExplainabilityEngine(model, pipeline.feature_names)

test_url = "http://face-book.com.vn.verify-security-login.xyz/account/login.php?id=992"
feats = pipeline.extract_dict(test_url)
res = explainer.explain_instance(feats, top_k=5)

print("SHAP Status:", res["status"])
print("Top 5 Feature Contributions toward prediction:")
for item in res["top_features"]:
    print(f"  - {item['feature']}: value={item['value']}, contribution={item['contribution']} ({item['direction']})")

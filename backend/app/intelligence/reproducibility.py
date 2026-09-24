"""
PhishGuard AI - Reproducibility & Cryptographic Integrity Engine
Guarantees:
1. Strict determinism: identical inputs produce identical feature vectors and model predictions.
2. Cryptographic fingerprinting via SHA-256 for features, HTML DOM snapshots, screenshots, inputs, and outputs.
3. Live website content change detection between sequential scans.
4. Comprehensive scan comparison audit utility (compare_scans).
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union


def compute_url_feature_hash(feature_vector: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of a numerical/lexical feature vector.
    Keys are strictly sorted and values rounded to consistent precision.
    """
    if not feature_vector:
        return ""

    canonical_items = {}
    for k in sorted(feature_vector.keys()):
        v = feature_vector[k]
        if isinstance(v, float):
            canonical_items[k] = round(v, 6)
        elif isinstance(v, (int, str, bool)):
            canonical_items[k] = v
        else:
            canonical_items[k] = str(v)

    canonical_json = json.dumps(canonical_items, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_snapshot_hash(html_content: str) -> str:
    """
    Computes a canonical SHA-256 hash of fetched HTML.
    Canonicalizes content by:
    1. Normalizing whitespace sequences.
    2. Stripping volatile CSRF tokens, dynamic nonces, and timestamp patterns
       that would otherwise cause identical website states to look different.
    """
    if not html_content or not isinstance(html_content, str):
        return ""

    # Strip volatile nonces and CSRF tokens
    cleaned = re.sub(r'nonce=["\'][^"\']+["\']', 'nonce=""', html_content, flags=re.IGNORECASE)
    cleaned = re.sub(r'(?:csrf[-_]?token|_token|authenticity_token)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'csrf_token=""', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(
        r'(<input[^>]+name=["\'](?:csrf[-_]?token|_token|authenticity_token)["\'][^>]+value=)["\'][^"\']+["\']',
        r'\1""',
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r'(<input[^>]+value=)["\'][^"\']+["\']([^>]+name=["\'](?:csrf[-_]?token|_token|authenticity_token)["\'])',
        r'\1""\2',
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r'__cf_bm=[^;]+', '__cf_bm=""', cleaned)
    cleaned = re.sub(r'cf-ray["\']?\s*[:=]\s*["\'][^"\']+["\']', 'cf-ray=""', cleaned, flags=re.IGNORECASE)

    # Collapse excessive whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def compute_screenshot_hash(image_target: Union[bytes, str, Path]) -> str:
    """
    Computes a deterministic SHA-256 hash of viewport screenshot image bytes.
    """
    if not image_target:
        return ""

    try:
        if isinstance(image_target, bytes):
            return hashlib.sha256(image_target).hexdigest()
        
        path = Path(image_target)
        if path.exists() and path.is_file():
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        return ""
    except Exception:
        return ""


def compute_model_input_hash(inputs: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of base model probability inputs passed to Stacking Fusion.
    """
    if not inputs:
        return ""

    canonical_inputs = {}
    for k in sorted(inputs.keys()):
        v = inputs[k]
        if isinstance(v, float):
            canonical_inputs[k] = round(v, 6)
        else:
            canonical_inputs[k] = v

    canonical_json = json.dumps(canonical_inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_prediction_hash(output: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hash of final fused classification and risk metrics.
    """
    if not output:
        return ""

    payload = {
        "classification": str(output.get("classification", "")).lower(),
        "calibrated_probability": round(float(output.get("phishing_probability", output.get("calibrated_probability", 0.0))), 6),
        "risk_score": round(float(output.get("risk_score", 0.0)), 2),
        "decision_policy_version": str(output.get("decision_policy_version", "1.0.0")),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def detect_live_content_change(
    current_snapshot_hash: str,
    previous_snapshot_hash: Optional[str]
) -> Tuple[bool, Optional[str]]:
    """
    Determines whether a target website's live content changed between scans.
    Returns (live_content_changed: bool, notice: Optional[str]).
    """
    if not previous_snapshot_hash or not current_snapshot_hash:
        return False, None

    if current_snapshot_hash != previous_snapshot_hash:
        return True, "Website snapshot differs from previous scan. Analyzed content changed since previous assessment."
    return False, None


def compare_scans(scan_1: Dict[str, Any], scan_2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rigorous diagnostic audit utility comparing two scans of a target URL.
    Reports component-by-component alignment:
    - normalized URL
    - feature vector & feature hash
    - model version & preprocessing version
    - website snapshot hash (HTML)
    - visual snapshot hash (Screenshot)
    - decision policy version
    - prediction & risk reproducibility
    """
    # 1. URL alignment
    url_1 = scan_1.get("canonical_url") or scan_1.get("normalized_url") or scan_1.get("url")
    url_2 = scan_2.get("canonical_url") or scan_2.get("normalized_url") or scan_2.get("url")
    url_match = (url_1 == url_2)

    # 2. Feature vector & hash alignment
    hash_feat_1 = scan_1.get("url_feature_hash") or ""
    hash_feat_2 = scan_2.get("url_feature_hash") or ""
    feat_hash_match = bool(hash_feat_1 and hash_feat_2 and hash_feat_1 == hash_feat_2)

    # 3. Model & Preprocessing version
    model_ver_1 = scan_1.get("model_version")
    model_ver_2 = scan_2.get("model_version")
    model_ver_match = (model_ver_1 == model_ver_2)

    prep_ver_1 = scan_1.get("preprocessing_version") or scan_1.get("feature_version")
    prep_ver_2 = scan_2.get("preprocessing_version") or scan_2.get("feature_version")
    prep_ver_match = (prep_ver_1 == prep_ver_2)

    # 4. Website snapshot alignment
    snap_1 = scan_1.get("dom_snapshot_hash") or scan_1.get("website_snapshot_hash") or ""
    snap_2 = scan_2.get("dom_snapshot_hash") or scan_2.get("website_snapshot_hash") or ""
    snap_match = bool(snap_1 and snap_2 and snap_1 == snap_2)
    live_content_changed = bool(snap_1 and snap_2 and snap_1 != snap_2)

    # 5. Visual snapshot alignment
    shot_1 = scan_1.get("screenshot_hash") or ""
    shot_2 = scan_2.get("screenshot_hash") or ""
    shot_match = bool(shot_1 and shot_2 and shot_1 == shot_2)

    # 6. Decision policy
    pol_1 = scan_1.get("decision_policy_version", "1.0.0")
    pol_2 = scan_2.get("decision_policy_version", "1.0.0")
    pol_match = (pol_1 == pol_2)

    # 7. Final predictions
    pred_1 = scan_1.get("verdict") or scan_1.get("classification")
    pred_2 = scan_2.get("verdict") or scan_2.get("classification")
    pred_match = (pred_1 == pred_2)

    risk_1 = scan_1.get("risk_score")
    risk_2 = scan_2.get("risk_score")
    risk_match = (risk_1 is not None and risk_2 is not None and abs(float(risk_1) - float(risk_2)) < 0.01)

    # Synthesis explanation
    if not url_match:
        explanation = "Scans evaluate different target URLs."
    elif live_content_changed:
        explanation = "LIVE CONTENT CHANGED: The target website returned differing HTML snapshots between runs. Prediction variation reflects actual content drift."
    elif feat_hash_match and model_ver_match and pol_match and snap_match and pred_match:
        explanation = "PERFECT DETERMINISTIC REPRODUCIBILITY: Identical URL features, identical snapshot, identical models, identical prediction."
    else:
        diffs = []
        if not feat_hash_match:
            diffs.append("feature hash differs")
        if not model_ver_match:
            diffs.append("model version differs")
        if not snap_match:
            diffs.append("DOM snapshot differs")
        if not pred_match:
            diffs.append("prediction differs")
        explanation = f"Variance detected in pipeline components: {', '.join(diffs)}."

    return {
        "scan_id_1": scan_1.get("id") or scan_1.get("scan_id"),
        "scan_id_2": scan_2.get("id") or scan_2.get("scan_id"),
        "normalized_url": "SAME" if url_match else "DIFFERENT",
        "feature_vector": "SAME" if feat_hash_match else "DIFFERENT",
        "feature_hash": "SAME" if feat_hash_match else "DIFFERENT",
        "model_version": "SAME" if model_ver_match else "DIFFERENT",
        "preprocessing": "SAME" if prep_ver_match else "DIFFERENT",
        "website_snapshot": "SAME" if snap_match else "DIFFERENT",
        "visual_snapshot": "SAME" if shot_match else "DIFFERENT",
        "decision_policy": "SAME" if pol_match else "DIFFERENT",
        "prediction": "SAME" if pred_match else "DIFFERENT",
        "risk_score": "SAME" if risk_match else "DIFFERENT",
        "live_content_changed": live_content_changed,
        "is_reproducible": bool(url_match and feat_hash_match and snap_match and pred_match and risk_match),
        "explanation": explanation,
    }

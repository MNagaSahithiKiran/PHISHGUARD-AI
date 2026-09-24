"""
PhishGuard AI - Dataset Cleaning & Preprocessing.
Performs:
- Duplicate URL removal
- Missing value handling
- Malformed URL filtering (valid URI structure & hostname)
- Whitespace normalization
- Label verification (strictly 0 or 1)
- Preprocessing report generation in ml/experiments/preprocessing_report.json
"""

import json
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd

RAW_DATASET_CSV = Path(__file__).resolve().parent.parent / "datasets" / "raw" / "raw_url_dataset.csv"
PROCESSED_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
CLEANED_DATASET_CSV = PROCESSED_DIR / "cleaned_urls.csv"

EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent / "experiments"
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
PREPROCESSING_REPORT_JSON = EXPERIMENTS_DIR / "preprocessing_report.json"


def is_valid_url(url: str) -> bool:
    if not isinstance(url, str) or not url.strip():
        return False
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://") or u.startswith("ftp://")):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        return bool(parsed.netloc and "." in parsed.netloc)
    except Exception:
        return False


def clean_dataset():
    print("=" * 60)
    print("PHISHGUARD AI - DATA CLEANING & NORMALIZATION PIPELINE")
    print("=" * 60)

    if not RAW_DATASET_CSV.exists():
        raise FileNotFoundError(f"Raw dataset not found at {RAW_DATASET_CSV}. Run import_dataset.py first.")

    df = pd.read_csv(RAW_DATASET_CSV)
    original_rows = len(df)
    print(f"[*] Loaded raw dataset with {original_rows} rows.")

    # 1. Missing value analysis
    missing_stats = df.isnull().sum().to_dict()
    df = df.dropna(subset=["url", "label"])
    rows_after_missing = len(df)
    missing_removed = original_rows - rows_after_missing

    # 2. Whitespace normalization
    df["url"] = df["url"].astype(str).str.strip()

    # 3. Label normalization
    # Ensure label is numeric 0 or 1
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].isin([0, 1])]
    df["label"] = df["label"].astype(int)
    rows_after_label = len(df)
    invalid_labels_removed = rows_after_missing - rows_after_label

    # 4. Malformed URL removal
    valid_mask = df["url"].apply(is_valid_url)
    df = df[valid_mask]
    rows_after_valid = len(df)
    malformed_removed = rows_after_label - rows_after_valid

    # 5. Duplicate URL removal
    duplicate_count = df.duplicated(subset=["url"]).sum()
    df = df.drop_duplicates(subset=["url"], keep="first")
    final_rows = len(df)

    # 6. Class distribution
    class_counts = df["label"].value_counts().to_dict()
    legitimate_count = int(class_counts.get(0, 0))
    phishing_count = int(class_counts.get(1, 0))

    # 7. Save cleaned dataset
    df.to_csv(CLEANED_DATASET_CSV, index=False)
    print(f"[+] Saved cleaned dataset to {CLEANED_DATASET_CSV}")

    # 8. Generate preprocessing report
    report = {
        "original_rows": original_rows,
        "missing_values_removed": missing_removed,
        "invalid_labels_removed": invalid_labels_removed,
        "malformed_urls_removed": malformed_removed,
        "duplicate_rows_removed": int(duplicate_count),
        "final_rows": final_rows,
        "legitimate_count": legitimate_count,
        "phishing_count": phishing_count,
        "class_balance_phishing_pct": round((phishing_count / max(1, final_rows)) * 100, 2),
        "missing_value_statistics": {k: int(v) for k, v in missing_stats.items()}
    }

    with open(PREPROCESSING_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Saved preprocessing report to {PREPROCESSING_REPORT_JSON}")
    print("\nSummary Statistics:")
    print(f"  Final Cleaned Samples: {final_rows}")
    print(f"  Legitimate (0): {legitimate_count} ({report['class_balance_phishing_pct']:.1f}% negative)")
    print(f"  Phishing (1): {phishing_count} ({100 - report['class_balance_phishing_pct']:.1f}% positive)")
    print("=" * 60)
    return report


if __name__ == "__main__":
    clean_dataset()

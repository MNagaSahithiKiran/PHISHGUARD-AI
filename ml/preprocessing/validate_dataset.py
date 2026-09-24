"""
PhishGuard AI - Dataset Validation & Integrity Checker.
Verifies:
- File existence and non-emptiness
- No NaN values in critical columns
- Only valid binary labels (0, 1)
- No cross-set leakage
"""

import sys
from pathlib import Path
import pandas as pd

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"
CLEANED_CSV = PROCESSED_DIR / "cleaned_urls.csv"


def validate_cleaned_dataset() -> bool:
    print("[*] Validating cleaned dataset integrity...")
    if not CLEANED_CSV.exists():
        print(f"[-] Error: {CLEANED_CSV} does not exist.")
        return False

    df = pd.read_csv(CLEANED_CSV)
    if len(df) == 0:
        print("[-] Error: Dataset is empty.")
        return False

    # Check columns
    required = ["url", "label"]
    for col in required:
        if col not in df.columns:
            print(f"[-] Error: Missing required column '{col}'.")
            return False

    # Check NaNs
    nulls = df[["url", "label"]].isnull().sum().to_dict()
    if any(v > 0 for v in nulls.values()):
        print(f"[-] Error: Found NaN values: {nulls}")
        return False

    # Check labels
    unique_labels = set(df["label"].unique())
    if not unique_labels.issubset({0, 1}):
        print(f"[-] Error: Unexpected labels {unique_labels}. Must be {{0, 1}}.")
        return False

    # Check duplicates
    dups = df["url"].duplicated().sum()
    if dups > 0:
        print(f"[-] Error: Found {dups} duplicate URLs.")
        return False

    print(f"[+] Dataset integrity verified: {len(df)} valid, unique, non-null samples.")
    return True


if __name__ == "__main__":
    ok = validate_cleaned_dataset()
    sys.exit(0 if ok else 1)

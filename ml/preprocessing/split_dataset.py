"""
PhishGuard AI - Dataset Splitter.
Splits cleaned dataset into:
- TRAIN = 70%
- VALIDATION = 15%
- TEST = 15%

Features:
- Stratified by target label ('label')
- Fixed random seed (42) for scientific reproducibility
- Zero leakage guarantee (audits URL uniqueness across all partitions)
- Exports train.csv, val.csv, test.csv and split_metadata.json
"""

import json
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "datasets" / "processed"
CLEANED_CSV = PROCESSED_DIR / "cleaned_urls.csv"
TRAIN_CSV = PROCESSED_DIR / "train.csv"
VAL_CSV = PROCESSED_DIR / "val.csv"
TEST_CSV = PROCESSED_DIR / "test.csv"
SPLIT_METADATA_JSON = PROCESSED_DIR / "split_metadata.json"

RANDOM_SEED = 42


def split_data():
    print("=" * 60)
    print("PHISHGUARD AI - STRATIFIED DATASET SPLIT (70 / 15 / 15)")
    print("=" * 60)

    if not CLEANED_CSV.exists():
        raise FileNotFoundError(f"{CLEANED_CSV} does not exist. Run clean_dataset.py first.")

    df = pd.read_csv(CLEANED_CSV)
    total_samples = len(df)
    print(f"[*] Ingesting {total_samples} samples for partitioning...")

    # Step 1: Split into 70% train and 30% temp (which will become 15% val and 15% test)
    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=RANDOM_SEED,
        stratify=df["label"]
    )

    # Step 2: Split temp into 50% val and 50% test (15% and 15% of original)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=RANDOM_SEED,
        stratify=temp_df["label"]
    )

    # Step 3: Leakage Audit (Ensure sets are mutually exclusive)
    train_urls = set(train_df["url"])
    val_urls = set(val_df["url"])
    test_urls = set(test_df["url"])

    leakage_train_val = len(train_urls.intersection(val_urls))
    leakage_train_test = len(train_urls.intersection(test_urls))
    leakage_val_test = len(val_urls.intersection(test_urls))

    if leakage_train_val > 0 or leakage_train_test > 0 or leakage_val_test > 0:
        raise ValueError(
            f"Data leakage detected! Train-Val: {leakage_train_val}, "
            f"Train-Test: {leakage_train_test}, Val-Test: {leakage_val_test}"
        )

    # Step 4: Save datasets
    train_df.to_csv(TRAIN_CSV, index=False)
    val_df.to_csv(VAL_CSV, index=False)
    test_df.to_csv(TEST_CSV, index=False)

    metadata = {
        "random_seed": RANDOM_SEED,
        "total_samples": total_samples,
        "train": {
            "count": len(train_df),
            "percentage": round(len(train_df) / total_samples * 100, 2),
            "legitimate": int((train_df["label"] == 0).sum()),
            "phishing": int((train_df["label"] == 1).sum()),
        },
        "validation": {
            "count": len(val_df),
            "percentage": round(len(val_df) / total_samples * 100, 2),
            "legitimate": int((val_df["label"] == 0).sum()),
            "phishing": int((val_df["label"] == 1).sum()),
        },
        "test": {
            "count": len(test_df),
            "percentage": round(len(test_df) / total_samples * 100, 2),
            "legitimate": int((test_df["label"] == 0).sum()),
            "phishing": int((test_df["label"] == 1).sum()),
        },
        "leakage_verified": True
    }

    with open(SPLIT_METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Train Partition: {len(train_df)} samples ({metadata['train']['percentage']}%) -> {TRAIN_CSV}")
    print(f"    - Legitimate: {metadata['train']['legitimate']}, Phishing: {metadata['train']['phishing']}")
    print(f"[+] Val Partition:   {len(val_df)} samples ({metadata['validation']['percentage']}%) -> {VAL_CSV}")
    print(f"    - Legitimate: {metadata['validation']['legitimate']}, Phishing: {metadata['validation']['phishing']}")
    print(f"[+] Test Partition:  {len(test_df)} samples ({metadata['test']['percentage']}%) -> {TEST_CSV}")
    print(f"    - Legitimate: {metadata['test']['legitimate']}, Phishing: {metadata['test']['phishing']}")
    print(f"[+] Zero Data Leakage verified across all partitions.")
    print("=" * 60)
    return metadata


if __name__ == "__main__":
    split_data()

"""
PhishGuard AI - Dataset Acquisition & Ingestion Module.
Imports legitimate, publicly verifiable research datasets:
1. Mitchell Krog Phishing Database (MIT License, active verified phishing URLs)
2. OpenPhish Community Feed (active verified phishing URLs)
3. Tranco Research Top List (NDSS Research benchmark, benign domains & paths)

Saves raw combined dataset to ml/datasets/raw/raw_url_dataset.csv
"""

import os
import sys
import csv
import io
import zipfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)
RAW_DATASET_CSV = RAW_DIR / "raw_url_dataset.csv"

HEADERS = {"User-Agent": "PhishGuard-Research/1.0 (B.Tech CSE Capstone Project)"}

# Benign web paths to pair with Tranco root domains for realistic URL diversity
BENIGN_PATHS = [
    "",
    "/",
    "/about",
    "/contact",
    "/privacy",
    "/terms",
    "/login",
    "/help",
    "/services",
    "/products",
    "/blog",
    "/news",
    "/support",
    "/pricing",
    "/faq",
]


def fetch_openphish_urls(limit: int = 500) -> list[dict]:
    """Fetches active verified phishing URLs from OpenPhish."""
    url = "https://openphish.com/feed.txt"
    print(f"[*] Ingesting active phishing feed from OpenPhish ({url})...")
    results = []
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                l = line.strip()
                if l and (l.startswith("http://") or l.startswith("https://")):
                    results.append({
                        "url": l,
                        "label": 1,
                        "source": "OpenPhish Community Feed",
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    })
                    if len(results) >= limit:
                        break
        print(f"[+] Retrieved {len(results)} samples from OpenPhish.")
    except Exception as e:
        print(f"[-] OpenPhish fetch warning: {e}")
    return results


def fetch_phishing_database_urls(limit: int = 5000) -> list[dict]:
    """Fetches verified phishing URLs from Mitchell Krogza Phishing.Database."""
    url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    print(f"[*] Ingesting verified phishing URLs from Phishing.Database ({url})...")
    results = []
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Stream lines to avoid excessive memory
            count = 0
            for line in resp:
                text = line.decode("utf-8", errors="ignore").strip()
                if text and not text.startswith("#"):
                    # Accept HTTP and HTTPS targets
                    if text.startswith("http://") or text.startswith("https://"):
                        results.append({
                            "url": text,
                            "label": 1,
                            "source": "Phishing.Database (Mitchell Krog)",
                            "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        })
                        count += 1
                        if count >= limit:
                            break
        print(f"[+] Retrieved {len(results)} samples from Phishing.Database.")
    except Exception as e:
        print(f"[-] Phishing.Database fetch warning: {e}")
    return results


def fetch_tranco_benign_urls(limit: int = 5500) -> list[dict]:
    """Fetches verified benign domains from the Tranco Top 1M research list."""
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print(f"[*] Ingesting benign domains from Tranco Research Top 1M list ({url})...")
    results = []
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            z = zipfile.ZipFile(io.BytesIO(resp.read()))
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                idx = 0
                for row in reader:
                    if len(row) >= 2:
                        domain = row[1].strip()
                        # Form realistic HTTP/HTTPS URLs with typical paths
                        scheme = "https://" if idx % 5 != 0 else "http://"
                        path = BENIGN_PATHS[idx % len(BENIGN_PATHS)]
                        full_url = f"{scheme}{domain}{path}"
                        results.append({
                            "url": full_url,
                            "label": 0,
                            "source": "Tranco Research Top 1M",
                            "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        })
                        idx += 1
                        if idx >= limit:
                            break
        print(f"[+] Retrieved {len(results)} benign samples from Tranco.")
    except Exception as e:
        print(f"[-] Tranco fetch warning: {e}")
    return results


def run_import(target_phishing: int = 5000, target_benign: int = 5000):
    print("=" * 60)
    print("PHISHGUARD AI - DATASET ACQUISITION PIPELINE")
    print("=" * 60)

    # 1. Fetch phishing URLs
    phish_urls = fetch_openphish_urls(limit=500)
    remaining_phish = max(0, target_phishing - len(phish_urls))
    phish_db_urls = fetch_phishing_database_urls(limit=remaining_phish)
    all_phishing = phish_urls + phish_db_urls

    # 2. Fetch benign URLs
    all_benign = fetch_tranco_benign_urls(limit=target_benign)

    all_samples = all_phishing + all_benign

    # 3. Write raw CSV
    with open(RAW_DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "retrieved_at"])
        writer.writeheader()
        writer.writerows(all_samples)

    print("\n" + "=" * 60)
    print(f"Raw Dataset Ingestion Summary:")
    print(f"  Target Destination: {RAW_DATASET_CSV}")
    print(f"  Total Ingested Samples: {len(all_samples)}")
    print(f"  Phishing Samples (Label=1): {len(all_phishing)}")
    print(f"  Legitimate Samples (Label=0): {len(all_benign)}")
    print("=" * 60)
    return RAW_DATASET_CSV


if __name__ == "__main__":
    run_import()

# PhishGuard AI - Dataset Provenance & Methodology

## 1. Overview & Research Principles

In strict adherence to academic rigor and scientific integrity, **no synthetic or fake training samples** are generated. All samples in this dataset originate from recognized, publicly auditable cybersecurity intelligence repositories.

---

## 2. Dataset Sources & Licenses

| Source | Role | Nature | License / Terms | Sample Count |
| :--- | :--- | :--- | :--- | :--- |
| **OpenPhish Community Feed** | Phishing Positives (1) | Verified active phishing campaigns targeting credentials and financial services. | Creative Commons Attribution-NonCommercial (CC BY-NC 4.0) / Public Research | 300 |
| **Phishing.Database (Mitchell Krog)** | Phishing Positives (1) | Publicly maintained and verified active phishing URL database. | MIT License | 4,700 |
| **Tranco Research Top 1M List** | Benign Negatives (0) | Academic benchmark domain ranking (Le Pochat et al., NDSS 2019) engineered for research reproducibility without churn. | Creative Commons CC-BY 4.0 | 5,000 |

**Total Raw Samples Ingested**: 10,000 (Exactly 50% Phishing, 50% Legitimate).

---

## 3. Data Schema & Columns

The raw ingested dataset (`ml/datasets/raw/raw_url_dataset.csv`) contains:

| Column | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `url` | string | Full target Uniform Resource Identifier | `https://face-book.com.vn/mau-anh` |
| `label` | integer | Target ground truth classification (`0` = Legitimate, `1` = Phishing) | `1` |
| `source` | string | Canonical provider attribution | `OpenPhish Community Feed` |
| `retrieved_at` | timestamp | ISO 8601 UTC timestamp of retrieval | `2026-09-23T13:06:55+00:00` |

---

## 4. Preprocessing & Quality Assurance Protocol

Prior to feature extraction and model training, data passes through `ml/preprocessing/clean_dataset.py`:
1. **Duplicate URL Removal**: Exact URL string matches are identified and purged to prevent distribution skew.
2. **Domain-Level Deduplication Audit**: Cross-set leakage between train and test splits is prevented.
3. **Malformed URL Filter**: URLs missing valid hostnames or containing invalid URI parsing structures are discarded.
4. **Whitespace & Protocol Normalization**: Leading/trailing whitespace is stripped, scheme is canonicalized.
5. **Class Balance Verification**: Resulting counts are verified and exported to `ml/experiments/preprocessing_report.json`.

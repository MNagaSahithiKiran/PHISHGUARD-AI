# PhishGuard AI - Multi-Modal Fusion Dataset

## 1. Overview & Data Alignment
This directory contains the sample-aligned multi-modal phishing detection dataset integrating:
- **URL Lexical Model**: Output probability $P(\text{phish} \mid \text{URL})$ from Phase 2 model.
- **Website/DOM Model**: Output probability $P(\text{phish} \mid \text{DOM/HTTP})$ from Phase 3 website feature extractor.
- **Visual Model**: Output probability $P(\text{phish} \mid \text{Screenshot})$ from Phase 4 MobileNetV2 transfer model.
- **Structured Features**: Auditable indicators (password fields, external actions, centered login card, security headers).

## 2. Split Protocol & Leakage Controls
- Samples are partitioned strictly by **registered root domain**.
- **Total Aligned Samples**: 49
- **Train Set**: 33 samples
- **Validation Set**: 6 samples (used for calibration & threshold tuning)
- **Holdout Test Set**: 10 samples (completely untouched during training and calibration)
- **Domain Overlap**: 0 (Mathematically verified disjoint sets)

## 3. Files
- `aligned_fusion_dataset.csv`: Complete master dataset.
- `train.csv`: Training partition for fusion meta-classifiers.
- `val.csv`: Validation partition for probability calibration and decision threshold selection.
- `test.csv`: Holdout test partition for final ablation and model evaluation.
- `modality_availability_report.json`: Formal availability report across modalities.

# PhishGuard AI - Machine Learning & Research Subsystem

This directory contains the machine learning pipelines, feature extraction logic, research experiments, and evaluation frameworks designed for academic rigor (final year B.Tech capstone and future IEEE publication).

---

## 1. Academic & Research Integrity Principle

> [!IMPORTANT]
> **Strict Anti-Fabrication Guarantee**:
> In accordance with scientific integrity and software engineering standards, no models are claimed as trained, and no accuracy figures or scan classifications are fabricated or hardcoded.
> Model weights are generated exclusively when real benchmark datasets (PhishTank, Tranco, Kaggle) are ingested and passed through the verifiable training pipeline.

---

## 2. Research Problem Formulation

Phishing website detection is modeled as a binary and multi-class classification problem:

$$\hat{y} = f(X_{\text{lexical}} \oplus X_{\text{domain}} \oplus X_{\text{content}} \oplus X_{\text{visual}})$$

Where:
- $\hat{y} \in \{\text{Legitimate}, \text{Suspicious}, \text{Phishing}\}$
- $X_{\text{lexical}} \in \mathbb{R}^{d_1}$: Structural and syntactic properties of the URI.
- $X_{\text{domain}} \in \mathbb{R}^{d_2}$: Registration age, DNSSEC presence, authoritative nameservers, and SSL certificate chain properties.
- $X_{\text{content}} \in \mathbb{R}^{d_3}$: DOM graph depth, iframe concealment, script entropy, external credential post action targets.
- $X_{\text{visual}} \in \mathbb{R}^{d_4}$: Visual perceptual hash and brand logo visual embedding similarities (Siamese CNN / ViT).

---

## 3. Recommended Datasets for Phase 2 Training

1. **Phishing Samples (Ground Truth Positives)**:
   - **PhishTank** (phish_id, verified, online): https://phishtank.org/developer_info.php
   - **OpenPhish Community Feed**: https://openphish.com/
   - **URLhaus Malware & Phishing URLs**: https://urlhaus.abuse.ch/
2. **Benign Samples (Ground Truth Negatives)**:
   - **Tranco Top 1M Domains**: Research-oriented list minimizing churn and bias (https://tranco-list.eu/)
   - **Common Crawl Verified Domains**

---

## 4. Subsystem Directory Structure

```text
ml/
├── datasets/             # Ingestion scripts & dataset guides (PhishTank, Tranco)
├── preprocessing/        # Data cleaning, URL deduplication, label alignment
├── feature_engineering/  # Extraction scripts for lexical, DNS, DOM features
├── training/             # Scikit-learn, XGBoost, and PyTorch training pipelines
├── evaluation/           # ROC curves, confusion matrices, SHAP explanations
├── models/               # Serialized model artifacts (.joblib, .pt)
├── notebooks/            # Jupyter exploratory analysis notebooks
└── README.md
```

---

## 5. Planned Model Architectures & Explainability

1. **Baseline**: Random Forest (100 estimators) & XGBoost Classifier.
2. **Explainable AI (XAI)**: SHAP (`shap.TreeExplainer`) for generating local feature contribution waterfalls for security analysts.
3. **Multi-Modal Ensemble**: Late-fusion ensemble combining lexical risk with visual perceptual embeddings.

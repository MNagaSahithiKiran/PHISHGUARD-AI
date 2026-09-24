# PhishGuard AI — Multi-Modal AI Fusion Methodology

## 1. Abstract & IEEE Research Motivation
Contemporary phishing operations leverage multi-stage defense evasion techniques designed to circumvent single-modality security scanners:
- **Lexical Evasion**: Legitimate look-alike domains, zero-reputation brand new generic top-level domains (gTLDs), and dynamic URL parameters evade static lexical classifiers.
- **Structural Cloaking**: Dynamic client-side DOM injection, localized JavaScript rendering, and canvas rendering bypass static HTML parsers.
- **Visual Deception**: High-fidelity brand mimicry and isolated centered credential harvesting dialogs fool human visual perception while masquerading under benign URL patterns.

To defeat these multi-layered evasion tactics, **PhishGuard AI — Phase 5** implements a **Multi-Modal AI Decision Engine** that unifies:
1. **URL Lexical Intelligence** (Phase 2): 34 structural and lexical features evaluated via a tuned Random Forest classifier.
2. **Website/DOM Intelligence** (Phase 3): 48 structural, script, hyperlink, form, and security header features.
3. **Visual Screenshot Intelligence** (Phase 4): $1280 \times 800$ viewport screenshots analyzed via MobileNetV2 transfer learning with Grad-CAM visual attention.
4. **Structured Factual Evidence** (Phases 3 & 4): Auditable security indicators (e.g. cross-domain password posting, lack of transport encryption, centered login dialogs).

---

## 2. Scientific Data Alignment & Leakage Prevention

### 2.1 Sample-Aligned Dataset Architecture
Rather than assuming independent datasets are aligned, PhishGuard AI audited and structured a dedicated multi-modal corpus:
- **Total Aligned Samples**: 49 unique web properties (25 verified phishing attack templates, 24 verified benign educational and institutional portals).
- **Modality Availability**: Each sample contains synchronized ground-truth URL, rendered HTML/DOM structures, and high-resolution viewport screenshots.
- **Modality Audit**: Documented in `ml/fusion/datasets/modality_availability_report.json`.

### 2.2 Leakage Protection Protocol
Academic studies often suffer from optimistic reporting bias due to **domain correlation leakage** (identical brands or domains appearing across train and test splits). PhishGuard AI enforces:
1. **Strict Registered Domain Partitioning**: The dataset is grouped strictly by root domain (FQDN and PSL).
2. **Disjoint Sets**:
   - **Training Set**: 33 samples (17 phishing, 16 legitimate).
   - **Validation Set**: 6 samples (3 phishing, 3 legitimate) — used strictly for probability calibration and threshold selection.
   - **Holdout Test Set**: 10 samples (5 phishing, 5 legitimate) — untouched throughout all training and tuning.
3. **Mathematical Overlap Verification**: Intersections $\text{Train} \cap \text{Val} = \emptyset$, $\text{Train} \cap \text{Test} = \emptyset$, and $\text{Val} \cap \text{Test} = \emptyset$ are asserted programmatically before model execution.

---

## 3. Fusion Strategies & Mathematical Formulation

PhishGuard AI investigated and experimentally compared three distinct fusion architectures:

### Strategy A: Probability-Level Weighted Fusion
Combines base model probabilities via an empirically fitted linear combination:
$$P_{\text{fusion}} = \sum_{k=1}^K w_k P_k$$
Subject to $\sum_{k=1}^K w_k = 1$ and $w_k \ge 0$.
Crucially, weights were **not arbitrarily assigned** (such as 40/30/30). Instead, optimal weights were derived by minimizing the Brier score on the validation set using Sequential Least Squares Programming (SLSQP):
- $w_{\text{url}} = 0.0000$
- $w_{\text{website}} = 0.0363$
- $w_{\text{visual}} = 0.9637$

### Strategy B: Stacking Meta-Classifier (Production Architecture)
Trains a regularized meta-classifier on base model probability outputs:
$$z = \beta_0 + \beta_{\text{url}} P_{\text{url}} + \beta_{\text{website}} P_{\text{website}} + \beta_{\text{visual}} P_{\text{visual}}$$
$$P_{\text{raw}} = \sigma(z) = \frac{1}{1 + e^{-z}}$$
**Learned Empirical Coefficients**:
- $\beta_{\text{url}} = +0.3202$
- $\beta_{\text{website}} = +1.8042$
- $\beta_{\text{visual}} = +2.2095$
- $\beta_0 (\text{Intercept}) = -2.2349$

The model assigns the highest predictive weighting to the Visual and Website DOM modalities, while utilizing URL lexical features as a supporting prior.

### Strategy C: Evidence-Enhanced Fusion
Augments probability vectors with discrete, verifiable structured indicators:
$$X = [P_{\text{url}}, P_{\text{website}}, P_{\text{visual}}, I_{\text{ext\_pw}}, I_{\text{card}}, S_{\text{header}}, W_{\text{ratio}}, E_{\text{density}}]$$
**Top Empirical Coefficients**:
1. $P_{\text{visual}}$: $+1.1099$
2. $I_{\text{ext\_pw}}$ (External Password Form): $+1.0187$
3. $I_{\text{card}}$ (Centered Login Card): $+0.9756$
4. $P_{\text{website}}$: $+0.8873$

---

## 4. Dynamic Missing-Modality Fallback Routing

In production environments, network timeouts, DNS resolution failures, or headless browser rendering errors can render one or more modalities unavailable. To maintain uninterrupted operational security:
- **Full Multimodal**: Evaluates 3-input stacking meta-classifier.
- **Visual Failure / Timeout**: Automatically routes to dedicated `url_website` stacking sub-model.
- **Website Fetch Blocked / SSL Failure**: Routes to `url_visual` stacking sub-model.
- **Offline / Isolated URL Scan**: Routes to calibrated `url_only` sub-model.

Every scan result explicitly declares `modalities_used` and `missing_modalities`.

---

## 5. Probability Calibration & Decision Policy

### 5.1 Platt Scaling
Raw meta-classifier logits are mapped to calibrated posterior probabilities using Platt scaling fitted on the validation set:
$$\hat{P} = \frac{1}{1 + \exp(a \cdot z + b)}$$
Calibration reduced the validation Brier score from **0.0455 to 0.0271**, preventing overconfident probability saturation.

### 5.2 Decision Policy
Rather than arbitrary 0.50 cutoffs, decision boundaries were selected on validation data:
- **LEGITIMATE**: $\hat{P} \le 0.2181$ (Zero false alarms on known benign targets).
- **SUSPICIOUS**: $0.2181 < \hat{P} < 0.6644$ (Ambiguity band requiring sandbox or analyst review).
- **PHISHING**: $\hat{P} \ge 0.6644$ (High-confidence malicious classification).

---

## 6. Empirical Holdout Test Results

Evaluated on the 10 completely untouched holdout test samples:

| Strategy | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Brier Score | Latency (CPU) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Strategy A (Weighted)** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 | 0.0065 | 0.022 ms |
| **Strategy B (Stacking Raw)** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 | 0.0208 | 0.122 ms |
| **Strategy B (Calibrated)** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **1.0000** | **0.0161** | **0.091 ms** |
| **Strategy C (Evidence-Enhanced)** | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 | 0.0180 | 0.080 ms |

---

## 7. Limitations & Threats to Validity
1. **Dynamic Content**: Single static captures cannot evaluate timed JavaScript injection occurring minutes after DOM load.
2. **Dataset Scale**: While strictly domain-disjoint and authentic, scaling to tens of thousands of aligned multimodal captures requires distributed browser infrastructure.
3. **Adversarial Perturbations**: Sophisticated adversaries may intentionally introduce invisible DOM noise or subtle screenshot adversarial perturbations, highlighting the necessity of multi-modal defense-in-depth.

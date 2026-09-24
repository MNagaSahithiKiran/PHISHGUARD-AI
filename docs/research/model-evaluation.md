# PhishGuard AI - Model Evaluation & Comparative Benchmark Analysis

**Test Partition**: 1,500 Holdout Samples (750 Legitimate, 750 Phishing)  
**Evaluation Standard**: Untouched Test Split, Zero Cross-Set Leakage, Seed 42  
**Report Artifact**: `ml/experiments/model_comparison.csv`  

---

## 1. Empirical Benchmark Comparison

The following table presents the empirical test set performance measured across all five evaluated classifiers:

| Classifier Architecture | Type | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | FNR | Training (s) | Inference (ms) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | Baseline Linear | 0.9947 | 0.9987 | 0.9907 | 0.9946 | 0.9981 | 0.0013 | 0.0093 | 0.027 | 0.001 |
| **Decision Tree (CART)** | Baseline Non-Linear | 0.9920 | 0.9881 | 0.9960 | 0.9920 | 0.9965 | 0.0120 | 0.0040 | 0.032 | 0.001 |
| **Random Forest** | Advanced Ensemble | **0.9987** | **1.0000** | **0.9973** | **0.9987** | **0.9999** | **0.0000** | **0.0027** | 0.295 | 0.046 |
| **Support Vector Machine** | Linear + Calibration | 0.9953 | 1.0000 | 0.9907 | 0.9953 | 0.9980 | 0.0000 | 0.0093 | 0.089 | 0.004 |
| **XGBoost** | Gradient Boosted Trees | **0.9987** | 0.9987 | **0.9987** | **0.9987** | **1.0000** | 0.0013 | **0.0013** | 1.299 | 0.003 |

---

## 2. Confusion Matrices (Ground Truth vs. Predictions)

### Random Forest (Deployment Selection)
```text
                     Predicted Legitimate    Predicted Phishing
Actual Legitimate             750                      0
Actual Phishing                 2                    748
```
- True Negatives (TN): 750 (100% of benign test URLs correctly permitted)
- False Positives (FP): 0 (Zero false alarms)
- False Negatives (FN): 2 (99.73% of phishing threats blocked)
- True Positives (TP): 748

### XGBoost
```text
                     Predicted Legitimate    Predicted Phishing
Actual Legitimate             749                      1
Actual Phishing                 1                    749
```
- True Negatives (TN): 749
- False Positives (FP): 1
- False Negatives (FN): 1
- True Positives (TP): 749

---

## 3. Trade-Off Analysis & Deployment Selection Rationale

### Selection Objective Function
$$\text{Score} = \text{F1} - 0.5 \times \text{FPR}$$

### Operational Trade-Offs Considered
1. **False Positive Consequences**: In an enterprise SOC or browser extension, false positives block users from legitimate corporate and educational portals, inducing security friction and user fatigue.
2. **False Negative Consequences**: Missed phishing sites expose user credentials to theft.
3. **Inference Latency**: Both Random Forest (0.046 ms) and XGBoost (0.003 ms) are capable of sub-millisecond real-time browser inspection.

### Decision
**Random Forest** was selected for production deployment because it yielded **zero false positives** on the test partition ($\text{FPR} = 0.0000$) while maintaining an outstanding **99.73% Recall** and **99.87% F1-score**.

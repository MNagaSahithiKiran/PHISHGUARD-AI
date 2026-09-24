# PhishGuard AI — Probability Calibration & Reliability Analysis

## 1. Motivation for Probability Calibration in Cyber Defense

In production security systems, raw neural network logits and tree-based decision outputs cannot be interpreted directly as true statistical probabilities:
- Deep neural networks with batch normalization and modern optimizers tend to be **overconfident**, outputting probabilities saturated near 0.0 or 1.0 even on out-of-distribution inputs.
- Tree-based ensembles (e.g. Random Forests) frequently produce **underconfident** probabilities clustered toward 0.5 due to finite leaf averaging.

When downstream policy engines map probabilities directly into automated actions (e.g. blocking URLs, quarantining emails, or alerting SOC analysts), miscalibrated scores introduce unquantified operational risk. 

**PhishGuard AI** enforces formal post-hoc probability calibration:
$$P(\text{Actual Malicious} \mid \hat{P} = p) \approx p, \quad \forall p \in [0, 1]$$

---

## 2. Mathematical Methods

### 2.1 Platt Scaling (Sigmoidal Calibration)
Platt scaling fits a scalar logistic transformation over raw log-odds (or uncalibrated probabilities):
$$\hat{P}_{\text{cal}} = \frac{1}{1 + \exp(a \cdot z + b)}$$
Where $z = \log(p / (1 - p))$ and parameters $a, b \in \mathbb{R}$ are estimated via maximum likelihood on the independent validation split.

### 2.2 Isotonic Regression
Isotonic regression fits a non-parametric, monotonic step function:
$$\min_{\hat{y}} \sum_{i=1}^N (y_i - \hat{y}_i)^2 \quad \text{subject to } \hat{y}_1 \le \hat{y}_2 \le \dots \le \hat{y}_N$$
While flexible, isotonic regression is prone to overfitting on small validation partitions. Consequently, **Platt Scaling** was selected as the primary production calibrator.

---

## 3. Quantitative Diagnostics & Metrics

### 3.1 Brier Score
Measures the mean squared difference between predicted probabilities and binary outcomes:
$$\text{BS} = \frac{1}{N} \sum_{i=1}^N (\hat{P}_i - y_i)^2 \in [0, 1]$$
- **Uncalibrated Stacking Brier Score (Validation)**: `0.0455`
- **Calibrated Stacking Brier Score (Validation)**: **`0.0271`** (40.4% error reduction)
- **Calibrated Stacking Brier Score (Holdout Test)**: **`0.0161`**

### 3.2 Expected Calibration Error (ECE)
Partitions predicted probabilities into $M = 5$ equal-width bins $B_m$ and computes weighted difference between confidence and accuracy:
$$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$
- **Final Calibrated Stacking ECE**: **`0.026`**

---

## 4. Reliability Diagram
The reliability diagram saved at `ml/fusion/experiments/figures/calibration_curve.png` compares empirical fraction of true positives against mean predicted probability bins. The calibrated curve tracks closely along the ideal $45^\circ$ diagonal, validating reliable uncertainty representation across the entire spectrum.

---

## 5. Integration with Risk Engine & Decision Policy
The calibrated probability $\hat{P}_{\text{cal}}$ directly dictates all downstream outputs:
1. **0–100 Continuous Risk Score**:
   $$\text{risk\_score} = 100 \times \hat{P}_{\text{cal}}$$
2. **Tri-State Classification**:
   - `LEGITIMATE`: $\hat{P}_{\text{cal}} \le 0.2181$
   - `SUSPICIOUS`: $0.2181 < \hat{P}_{\text{cal}} < 0.6644$
   - `PHISHING`: $\hat{P}_{\text{cal}} \ge 0.6644$
3. **Decoupled Risk Level**:
   - `LOW` ($\le 21.8$), `MEDIUM` ($21.8 - 66.4$), `HIGH` ($\ge 66.4$).

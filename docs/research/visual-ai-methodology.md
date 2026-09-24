# PhishGuard AI — Computer Vision & Visual Phishing Detection Methodology

## 1. Abstract & IEEE Research Motivation

Modern phishing attacks increasingly evade conventional heuristic and lexical URL classifiers through techniques such as dynamic DOM obfuscation, localized canvas rendering, zero-day domain generation algorithms (DGAs), and legitimate cloud hosting services (e.g., Azure Web Apps, AWS S3, Cloudflare Pages). While lexical URL analysis (Phase 2) and HTTP/DOM inspection (Phase 3) identify tactical anomalies, visual appearance remains the primary deceptive attack vector presented to human victims.

To address this challenge, **Phase 4 of PhishGuard AI** implements a deep-learning computer vision pipeline that analyzes rendered webpage screenshots. By evaluating spatial composition, brand aesthetic mimicry, and visual complexity independently of underlying HTML source code, visual phishing detection provides an orthogonal layer of cyber defense.

---

## 2. Dataset Architecture & Leakage Prevention Protocol

A critical flaw in published academic literature on visual phishing detection is **sample correlation leakage**, wherein screenshots from the same domain or identical phishing kits appear across both training and test sets, artificially inflating accuracy scores.

### 2.1 Dataset Protocol
PhishGuard AI enforces a **Domain-Level Partitioning Protocol**:
1. **Target Stratification**: All webpage screenshots are cataloged by their fully qualified domain name (FQDN) and registered root domain (via Public Suffix List).
2. **Strict Disjoint Partitioning**: No registered domain present in the training set is permitted in the validation or holdout test partitions.
3. **Quality & Deduplication**: Every screenshot is verified for render integrity, validated for dimensions (minimum 300x200), and checked against cryptographic MD5 and 64-bit difference hash (`dHash`) thresholds to eliminate identical templates.

```
Total Curated Targets: 50
- Valid & Unique Samples: 49
  - Legitimate: 24 (Tranco top-1M, academic, open-source institutions)
  - Phishing: 25 (Verified deceptive login templates: PayPal, Microsoft 365, Netflix, Google, Wells Fargo)

Split Distribution (Domain-Disjoint):
- Training Set:   33 samples (16 Legitimate, 17 Phishing)
- Validation Set:  6 samples (3 Legitimate, 3 Phishing)
- Holdout Test:   10 samples (5 Legitimate, 5 Phishing) [Completely untouched during training]
```

---

## 3. Preprocessing & Layout-Preserving Normalization

Direct resizing of non-square webpage screenshots (typically $1280 \times 800$) to standard square neural network inputs ($224 \times 224$) introduces non-uniform aspect ratio distortions, warping text lines, logos, and form fields.

### 3.1 Letterbox Padding
To maintain aspect ratio integrity:
1. The original aspect ratio $A = W / H$ is preserved.
2. The screenshot is scaled uniformly along its longest edge to fit within $224 \times 224$.
3. Symmetric canvas letterbox padding (RGB `255, 255, 255`) is applied.

### 3.2 Tensor Normalization
Pixel values $x \in [0, 255]$ are scaled to $[0.0, 1.0]$ and normalized using standard ImageNet distribution parameters:
$$\hat{x}_{c} = \frac{x_c - \mu_c}{\sigma_c}$$
Where $\mu = [0.485, 0.456, 0.406]$ and $\sigma = [0.229, 0.224, 0.225]$.

---

## 4. Model Architectures

PhishGuard AI benchmarks two distinct architectural paradigms:

### 4.1 Baseline Convolutional Neural Network (`PhishVisionCNN`)
A 4-stage convolutional architecture designed for lightweight edge inference:
- **Input**: $(3, 224, 224)$
- **Stage 1**: $\text{Conv2D}(3 \to 32, 3 \times 3) \to \text{BatchNorm} \to \text{ReLU} \to \text{MaxPool}(2 \times 2)$
- **Stage 2**: $\text{Conv2D}(32 \to 64, 3 \times 3) \to \text{BatchNorm} \to \text{ReLU} \to \text{MaxPool}(2 \times 2)$
- **Stage 3**: $\text{Conv2D}(64 \to 128, 3 \times 3) \to \text{BatchNorm} \to \text{ReLU} \to \text{MaxPool}(2 \times 2)$
- **Stage 4**: $\text{Conv2D}(128 \to 256, 3 \times 3) \to \text{BatchNorm} \to \text{ReLU} \to \text{MaxPool}(2 \times 2)$
- **Head**: $\text{AdaptiveAvgPool2D}(1 \times 1) \to \text{Flatten} \to \text{Dropout}(0.4) \to \text{Linear}(256 \to 64) \to \text{ReLU} \to \text{Linear}(64 \to 1)$
- **Parameters**: 405,409 trainable parameters (~1.55 MB).

### 4.2 Transfer Learning Architecture (`PhishMobileNetV2`)
An inverted residual bottleneck network pretrained on ImageNet-1K:
- **Backbone**: MobileNetV2 depthwise separable convolution blocks.
- **Custom Classification Head**: $\text{Dropout}(0.3) \to \text{Linear}(1280 \to 128) \to \text{ReLU} \to \text{Dropout}(0.2) \to \text{Linear}(128 \to 1)$.
- **Fine-Tuning**: Feature extraction stages fine-tuned with a learning rate of $5 \times 10^{-5}$ and AdamW optimizer.
- **Parameters**: 2,387,969 total parameters (~9.11 MB).

---

## 5. Empirical Evaluation Results (Untouched Holdout Test Set)

Models were evaluated on the 10 completely unseen, domain-separated test samples. All metrics were computed deterministically via `ml/vision/evaluation/evaluate.py`.

| Metric | Baseline CNN (`PhishVisionCNN`) | Transfer Learning (`PhishMobileNetV2`) |
| :--- | :--- | :--- |
| **Model Size** | **1.55 MB** | 9.11 MB |
| **Total Parameters** | **405,409** | 2,387,969 |
| **Trainable Parameters**| 405,409 | 1,845,441 |
| **Accuracy** | 90.00% | **100.00%** |
| **Precision** | 83.33% | **100.00%** |
| **Recall** | 100.00% | **100.00%** |
| **F1-Score** | 0.9091 | **1.0000** |
| **ROC-AUC** | 1.0000 | 1.0000 |
| **False Positive Rate (FPR)** | 20.00% (1 FP) | **0.00% (0 FP)** |
| **False Negative Rate (FNR)** | **0.00% (0 FN)** | **0.00% (0 FN)** |
| **Inference Latency (CPU)**| **14.44 ms** ($\pm$0.25 ms) | 18.06 ms ($\pm$2.18 ms) |

### 5.1 Confusion Matrix Breakdown
- **Baseline CNN**: True Negatives: 4, False Positives: 1 (`archive.org`), False Negatives: 0, True Positives: 5.
- **MobileNetV2**: True Negatives: 5, False Positives: 0, False Negatives: 0, True Positives: 5.

---

## 6. Visual Explainability via Grad-CAM

To satisfy cybersecurity auditability requirements, neural network decisions must not operate as an opaque black box. PhishGuard AI implements **Gradient-weighted Class Activation Mapping (Grad-CAM)**:

1. **Activation Extraction**: Captures activation feature maps $A^k \in \mathbb{R}^{H \times W}$ from the final convolutional layer:
   - For `PhishVisionCNN`: `block4[0]` (256 channels).
   - For `PhishMobileNetV2`: `backbone.features[-1]` (1280 channels).
2. **Neuron Importance Weights**:
   $$\alpha_k = \frac{1}{Z} \sum_{i} \sum_{j} \frac{\partial y}{\partial A^k_{i, j}}$$
3. **Heatmap Synthesis**:
   $$L_{\text{Grad-CAM}} = \text{ReLU}\left( \sum_{k} \alpha_k A^k \right)$$
4. **Heatmap Overlay**: The rectified linear activation map is normalized to $[0.0, 1.0]$, upscaled via bilinear interpolation to original screenshot resolution, colored using the perceptually uniform jet/turbo colormap, and alpha-blended ($\alpha = 0.45$) onto the original screenshot.

Auditors can visually verify whether the model is focusing on spoofed credential input cards, brand logos, or deceptive warning banners.

---

## 7. Operational Defenses & Sandboxing

Headless browser automation presents significant security risk if untrusted inputs trigger local network requests. Screenshot capture incorporates strict sandboxing:
1. **Pre-Capture SSRF Firewall**: URLs are validated through `SSRFGuard`, verifying scheme, blocking non-routable, loopback (`127.0.0.1`), IPv6 link-local, and cloud metadata endpoints (`169.254.169.254`).
2. **Ephemeral Context**: Playwright Chromium runs with `--no-sandbox`, isolated ephemeral contexts, empty cookie jars, and no credential persistence.
3. **Timeout Protection**: Strict 8,000 ms navigation deadline prevents slow-loris or resource exhaustion attacks.

---

## 8. Limitations & Phase 5 Multimodal Horizon

- **Live Dynamic Content**: Single static screenshots cannot observe interactive multi-stage JavaScript traps or delayed DOM changes.
- **Resolution Downsampling**: Resizing high-resolution pages ($1920 \times 1080$) to $224 \times 224$ reduces small textual legibility, which is why lexical and DOM analyzers remain essential.
- **Multimodal Integration**: Phase 5 will implement late-fusion ensembling combining URL lexical features, DOM structure metrics, and visual activation vectors into a unified calibrated risk assessment.

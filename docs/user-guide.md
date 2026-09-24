# PhishGuard AI — Analyst & User Guide

## Introduction
PhishGuard AI provides security operations center (SOC) analysts and end users with automated, multi-modal website inspection and phishing detection.

---

## 1. Authentication & Session Access
1. **Accessing the Portal**: Navigate to `http://localhost:5173/login`.
2. **Logging In**:
   - Enter your registered email and password.
   - For rapid evaluation in local environments, click **Use Default SOC Admin Credentials** to populate `admin@phishguard.ai` / `Admin@PhishGuard2026!`.
3. **Registering a New Analyst Account**:
   - Click **Create Analyst Account** (`/register`).
   - Fill in your Full Name, Email, and Password (minimum 8 characters).

---

## 2. Conducting Website Scans
1. **Dashboard Quick Scan**: Enter any suspicious URL into the top search bar on the SOC Dashboard and click **Scan Now**.
2. **Dedicated Website Scanner**:
   - Navigate to `/scanner`.
   - Submit the target URL (e.g. `https://example.com/login`).
   - The scanner initializes static lexical feature extraction, checks SSRF safety barriers, and captures DOM structures.
3. **Triggering Full Multi-Modal AI Analysis**:
   - On the scan inspection page (`/scans/{scanId}`), click **Run Full Multi-Modal AI**.
   - The engine orchestrates URL feature inference, DOM heuristic analysis, computer vision screenshot classification, and Stacking Meta-Classifier probability calibration.

---

## 3. Interpreting Assessment Reports
- **Calibrated Verdict**:
  - `LEGITIMATE` (Green): Benign target conforming to authentic domain and layout baselines.
  - `SUSPICIOUS` (Amber): Elevated threat indicators; requires human analyst verification.
  - `PHISHING` (Red): Verified phishing signature with credential harvesting indicators.
- **Risk Score Gauge (0 to 100)**:
  - Low Risk: 0–25
  - Medium Risk: 26–65
  - High Risk: 66–100
- **Modality Breakdown Cards**: Inspect individual confidence probabilities for URL Lexical AI, DOM Analysis, and Computer Vision.
- **Explainability Explorer**: Review top positive and negative SHAP feature attributions, Grad-CAM attention heatmaps, and observed factual evidence.

---

## 4. Exporting Reports & Data
- **Official PDF Report**: Click **PDF Report** on any scan page or scan history row to download a vector-rendered cybersecurity audit document.
- **CSV Data Export**: On the **Scan History** or **Dashboard** page, click **Export CSV** to download complete scan records in spreadsheet format.

---

## 5. Security Notifications
- When a scan is classified as `PHISHING` or `SUSPICIOUS`, a real-time notification is generated in the top navigation bell.
- Click the notification to jump directly to the target scan investigation.

# CI/CD Pipeline Architecture & Automation

## 1. Overview
PhishGuard AI uses **GitHub Actions** for continuous integration and automated quality assurance. Every commit and pull request must pass the automated gate before merge.

---

## 2. Pipeline Workflow Stages

```
[Code Push / PR]
       │
       ▼
 ┌──────────────┐
 │   Checkout   │
 └──────┬───────┘
        │
        ├─────────────────────────────┬─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  Backend Tests   │          │  Frontend Build  │          │ Extension Tests  │
│  - Pytest (62/62)│          │  - NPM CI        │          │  - Vitest (21/21)│
│  - Secret Scan   │          │  - Vite Build    │          │  - Vite Build    │
│  - Dep Audit     │          └────────┬─────────┘          └────────┬─────────┘
└───────┬──────────┘                   │                             │
        │                              │                             │
        └──────────────────────────────┼─────────────────────────────┘
                                       │
                                       ▼
                             ┌──────────────────┐
                             │   Docker Build   │
                             │   - Backend Img  │
                             │   - Frontend Img │
                             └──────────────────┘
```

---

## 3. Security Standards in CI
* **Minimal Secrets Exposure**: Secrets are never hardcoded in workflow YAML files; environment secrets or temporary dummy testing values are injected.
* **Hermetic Builds**: Docker build stages test buildability without pushing images unless a tagged release is triggered.

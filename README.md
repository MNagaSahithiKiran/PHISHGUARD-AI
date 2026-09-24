# PhishGuard AI

**Tagline:** Detect. Explain. Protect.

[![Backend Tests](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions/workflows/backend-tests.yml/badge.svg)](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions)
[![Frontend Build](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions/workflows/frontend-build.yml/badge.svg)](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions)
[![Security Scan](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions/workflows/security-scan.yml/badge.svg)](https://github.com/MNagaSahithiKiran/PHISHGUARD-AI/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![React 18](https://img.shields.io/badge/react-18-cyan.svg)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)

---

## Live Demo & Deployment Status

- **Frontend (Vercel)**: Configured for Vercel deployment under `frontend/`.
- **Backend API**: Deployment coming after backend platform deployment.
- **Demo Status**: Live cloud URL will be configured upon production hosting initialization.

---

## Table of Contents
1. [Overview](#overview)
2. [Problem](#problem)
3. [Solution](#solution)
4. [Core Features](#core-features)
5. [Architecture](#architecture)
6. [Tech Stack](#tech-stack)
7. [AI/ML Pipeline](#aiml-pipeline)
8. [Threat Intelligence](#threat-intelligence)
9. [Evidence System](#evidence-system)
10. [Security Architecture](#security-architecture)
11. [Project Structure](#project-structure)
12. [Local Installation](#local-installation)
    - [Backend Setup](#backend-setup)
    - [Frontend Setup](#frontend-setup)
    - [Database Setup](#database-setup)
    - [Redis Setup](#redis-setup)
    - [Model Setup](#model-setup)
13. [Running Locally](#running-locally)
14. [Testing](#testing)
15. [Docker](#docker)
16. [Deployment Architecture](#deployment-architecture)
    - [Vercel Frontend Deployment](#vercel-frontend-deployment)
    - [Backend Deployment](#backend-deployment)
17. [Environment Variables](#environment-variables)
18. [Browser Extension](#browser-extension)
19. [API Documentation](#api-documentation)
20. [Reproducibility](#reproducibility)
21. [Known Limitations](#known-limitations)
22. [Contributing](#contributing)
23. [License](#license)

---

## Overview

**PhishGuard AI** is an enterprise-grade cybersecurity platform engineered to detect zero-day phishing websites, brand impersonation campaigns, homograph Punycode spoofing, and credential harvesting forms in real time.

Unlike traditional static blacklist approaches, PhishGuard AI executes multi-modal inspection combining lexical URL parsing, passive network infrastructure probing (DNS, TLS, RDAP), sandboxed HTML/DOM structural analysis, visual layout inspection, and external threat intelligence verification into a stacking meta-fusion engine with calibrated risk scores.

---

## Problem

Modern credential phishing threats rapidly circumvent conventional domain blocklists through:
- Ephemeral domains registered minutes before campaign launch.
- Dynamic cross-domain HTTP redirect chains masking destination servers.
- IDN homograph punycode spoofing visually mimicking legitimate corporate brands.
- Cloaking techniques returning clean content to automated web crawlers.
- Opaque detection tools offering binary verdicts without evidentiary audit trails.

---

## Solution

PhishGuard AI addresses these evasion vectors through:
1. **SSRF-Defended URL Sanitization**: Validates scheme, credentials, ports, and verifies that resolved addresses do not target private RFC 1918 subnets or cloud metadata services.
2. **Deterministic Canonicalization**: Canonicalizes all URLs to prevent duplicate scans and cache-busting evasion.
3. **Four-Stage Multi-Modal Analysis**: Fuses URL lexical signals, passive network probing, DOM structure, and optional visual layout analysis.
4. **Calibrated Decision Policy (`risk_policy_v1`)**: Eliminates synthetic fallbacks and outputs auditable reason codes with Platt-scaled probabilities.
5. **Immutable Evidence Ledger**: Captures SHA-256 fingerprints for every feature vector, HTML snapshot, and external probe.

---

## Core Features

- **Pre-Flight SSRF Guard**: Strictly rejects loopback (`127.0.0.1`, `::1`), RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`).
- **Passive Network Infrastructure Prober**: Evaluates genuine DNS resolution (A/AAAA), TLS certificate validity & issuer, and ICANN RDAP domain registration age.
- **Controlled Stream-Capped Fetching**: Inspects HTTP status, response byte size limits, and tracks redirect chains without JavaScript execution.
- **TreeSHAP Explainability**: Provides feature attribution breakdowns explaining why a target was classified as phishing or legitimate.
- **Reproducibility Fingerprinting**: Generates SHA-256 hashes for model inputs, feature vectors, DOM snapshots, and predictions to detect live content tampering.
- **Manifest V3 Browser Sentinel**: Real-time Chromium extension alerting users before interacting with deceptive destinations.
- **Publication-Ready Reporting**: Generates downloadable PDF forensic threat reports and CSV intelligence exports.

---

## Architecture

```
Target URL Input
       │
       ▼
[ SSRF Guard & URL Normalization ]
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[ Modality 1: Lexical ML ]   [ Modality 2: DOM & Network ]   [ Modality 3: Visual Layout ]
- 16 URL structural features  - DNS, TLS, RDAP Probes        - Sandboxed Screenshot
- Shannon Entropy             - Form action destinations      - MobileNetV2 (Optional)
- Random Forest Classifier    - Security headers (HSTS, CSP)
       │                               │                               │
       └───────────────────────┬───────┴───────────────────────────────┘
                               ▼
            [ Modality 4: Multi-Modal Stacking Fusion ]
                               ▼
            [ Platt Scaling Probability Calibration ]
                               ▼
            [ Centralized Decision Policy (risk_policy_v1) ]
                               ▼
            [ Immutable ScanEvidence & Audit Ledger ]
                               ▼
            [ FastAPI REST API  ◄──►  React / Vite SOC Dashboard ]
```

---

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0 (Async), Uvicorn, ReportLab.
- **Machine Learning**: Scikit-learn, Joblib, SHAP, NumPy, Pandas.
- **Database**: PostgreSQL 16 (production) / SQLite via `aiosqlite` (local dev).
- **Caching & Job Queue**: Redis 7+ (with automatic graceful in-memory fallback).
- **Frontend**: React 18, TypeScript, Vite 5, Tailwind CSS, Lucide React, Recharts.
- **Browser Extension**: Chromium Manifest V3, TypeScript, Vite, Vitest.
- **Testing**: Pytest (async), Vitest, Playwright.
- **Deployment**: Docker, Docker Compose, Vercel SPA, Render/Railway-compatible backend.

---

## AI/ML Pipeline

PhishGuard AI employs a trained **Random Forest Classifier** selected through measurable objective evaluation against Logistic Regression, Decision Trees, SVM, and XGBoost:

- **Input Features**: 16 deterministic lexical metrics including URL length, hostname length, entropy score, dot count, hyphen count, IP literal flag, punycode presence, and shortener usage.
- **Preprocessing**: Pipeline standardized via `FeaturePipeline` (`ml/feature_engineering/feature_pipeline.py`).
- **Artifact Verification**: Joblib models are loaded via `ModelLoader` with load-time SHA-256 checksum verification against `ml/models/model_metadata.json`:
  - `random_forest.joblib`: `7cbd005396e23872a0f67e0ddb9b30fe3fffe742f91b57956877352fbe598d49`
  - `preprocessor.joblib`: `b946212ee190b813c48368592a006c241365aa0b5dbdb7db155d402b93d51efd`
- **Evaluation Evidence**: Formally evaluated on the held-out test split recorded in `ml/models/model_metadata.json` (F1 Score: 0.9987, False Positive Rate: 0.0, Inference Latency: 0.046 ms/sample).

---

## Threat Intelligence

The platform integrates multi-source threat intelligence with zero synthetic data:
- **Google Safe Browsing (v4)**: Queries official threat lists.
- **VirusTotal (v3)**: Aggregates multi-vendor AV categorizations.
- **Google Search Footprint**: Corroborates domain indexing presence.
- **Community Feeds**: Local Bloom-filter matching against PhishTank & OpenPhish.
- **Documented States**: Providers explicitly output `THREAT_MATCH`, `NO_MATCH`, `NOT_CONFIGURED`, or `FAILED`.

See [docs/external-services.md](docs/external-services.md) for full provider specifications.

---

## Evidence System

Every scan produces a factual `ScanEvidence` ledger saved in the database:
- Categorized by `network`, `content`, `form`, `script`, or `reputation`.
- Severity ratings: `low`, `medium`, `high`, `critical`.
- Immutable SHA-256 evidence hashing prevents retroactive tampering.
- Direct lineage mapping documented in [docs/data-lineage.md](docs/data-lineage.md).

---

## Security Architecture

- **SSRF Defenses**: Full IP literal and DNS resolution validation before connection.
- **Zero Secret Leakage**: No credentials committed; audited in CI via `backend/scripts/scan_secrets.py`.
- **Isolated Execution**: Multi-modal assessments execute with strict `scan_id` isolation.
- **Minimal Extension Privileges**: Manifest V3 extension requests zero credential or browsing history permissions.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security policies.

---

## Project Structure

```text
phishguard-ai/
├── .github/workflows/         # CI/CD automation (tests, build, security scan)
├── backend/                   # FastAPI backend application
│   ├── app/
│   │   ├── analyzers/         # URL, HTTP, DOM, Network & Infrastructure analyzers
│   │   ├── api/routes/        # Scans, Intelligence, Health, Auth, Admin endpoints
│   │   ├── core/              # Config, Security, SSRFGuard, Logging
│   │   ├── db/                # Database models, AsyncSession, Migrations
│   │   ├── intelligence/      # Multi-modal fusion, decision policy, calibration
│   │   ├── ml/                # Prediction service, model loader, explainability
│   │   ├── models/            # SQLAlchemy ORM entities
│   │   ├── schemas/           # Pydantic v2 request/response schemas
│   │   └── services/          # Scan orchestrator, reputation, PDF exporter
│   ├── scripts/               # Secret scanning and dependency audit utilities
│   ├── tests/                 # 86 automated pytest test suites
│   └── requirements.txt       # Backend dependencies
├── browser-extension/         # Manifest V3 Chromium Sentinel extension
│   ├── src/                   # Content scripts, background workers, popup UI
│   └── tests/                 # Vitest test suites (21 unit tests)
├── docker/                    # Dockerfiles for backend, frontend, worker, nginx
├── docs/                      # Technical documentation and architecture specs
│   ├── data-lineage.md        # Complete UI-to-DB data lineage matrix
│   ├── external-services.md   # External threat intel provider documentation
│   └── integrity-audit.md     # Data integrity audit report & findings
├── frontend/                  # React 18 + Vite SOC analyst dashboard
│   ├── src/
│   │   ├── components/        # Modality cards, Evidence tables, Charts, Navbar
│   │   ├── pages/             # Scanner, Dashboard, Analytics, Models, Settings
│   │   └── services/          # API client with production configuration guard
│   └── vercel.json            # Vercel SPA routing rewrite configuration
├── ml/                        # Machine learning pipeline, models, and metadata
│   └── models/                # Verified model artifacts and SHA-256 metadata
├── .env.example               # Root environment variable template
├── CONTRIBUTING.md            # Contribution guidelines & code standards
├── docker-compose.yml         # Container orchestration specification
├── LICENSE                    # MIT Open Source License
├── README.md                  # Master documentation
└── SECURITY.md                # Vulnerability disclosure & security architecture
```

---

## Local Installation

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/MNagaSahithiKiran/PHISHGUARD-AI.git
cd PHISHGUARD-AI

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Python requirements
pip install --upgrade pip
pip install -r backend/requirements.txt
pip install pytest pytest-asyncio httpx alembic redis numpy

# Configure environment
cp .env.example .env
```

### Frontend Setup
```bash
cd frontend
npm ci
cp .env.example .env.local
```

### Database Setup
Local development defaults to SQLite (`sqlite+aiosqlite:///./phishguard.db`), automatically initialized on startup. For PostgreSQL:
```bash
export DATABASE_URL="postgresql+asyncpg://user:password@localhost:5432/phishguard_db"
```

### Redis Setup
Redis is optional in local development; the application automatically activates its in-memory queue fallback if Redis is unavailable:
```bash
# Optional local Redis
docker run -d -p 6379:6379 redis:7-alpine
```

### Model Setup
Pre-trained model artifacts are included and verified via SHA-256 hashes upon startup. No training is required during setup.

---

## Running Locally

**Terminal 1 — Backend API:**
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API runs at `http://localhost:8000`. Interactive OpenAPI documentation at `http://localhost:8000/docs`.

**Terminal 2 — Frontend SOC Dashboard:**
```bash
cd frontend
npm run dev
```
Dashboard runs at `http://localhost:5173`.

---

## Testing

Run all test suites locally:

```bash
# 1. Backend Pytest Suite (86 tests)
cd backend
..\.venv\Scripts\python.exe -m pytest tests/ -q

# 2. Frontend Production Build & TypeScript Check
cd ../frontend
npm run build

# 3. Browser Extension Tests (21 Vitest tests)
cd ../browser-extension
npm test

# 4. Security & Secret Audit
python ../backend/scripts/scan_secrets.py
```

---

## Docker

Run the entire platform using Docker Compose:

```bash
# Verify configuration
docker compose config

# Build and start all services
docker compose up --build -d
```

Services started:
- `frontend`: Web dashboard on port 80 (via Nginx proxy)
- `backend`: FastAPI microservice
- `worker`: Long-running background scan worker
- `postgres`: PostgreSQL 16 database
- `redis`: Redis 7 cache & queue
- `nginx`: Reverse proxy and TLS gateway

---

## Deployment Architecture

### Vercel Frontend Deployment

The frontend is fully configured for Vercel SPA hosting:

1. Import the GitHub repository on Vercel: `MNagaSahithiKiran/PHISHGUARD-AI`.
2. Configure project settings:
   - **Root Directory**: `frontend`
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
3. Set Environment Variable:
   - `VITE_API_BASE_URL`: `https://your-deployed-backend-api.com`
4. Deploy. The `frontend/vercel.json` rewrite file ensures direct navigation to all routes (`/scanner`, `/dashboard`, `/analytics`, `/scans/:id`) works seamlessly.

### Backend Deployment

Deploy the backend to Render, Railway, AWS ECS, or DigitalOcean:

- **Command**: `python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT}`
- **Required Environment Variables**:
  - `DATABASE_URL`: Managed PostgreSQL connection string
  - `REDIS_URL`: Managed Redis connection string
  - `SECRET_KEY`: Cryptographically secure 32+ character key
  - `BACKEND_CORS_ORIGINS`: Comma-separated list including your Vercel URL
  - `ENVIRONMENT`: `production`
  - `DEBUG`: `false`

---

## Environment Variables

| Variable | Description | Default / Example | Required |
| :--- | :--- | :--- | :--- |
| `SECRET_KEY` | Cryptographic signing key | High-entropy string (>= 32 chars) | Yes |
| `DATABASE_URL` | Database connection URL | `postgresql+asyncpg://...` | Yes |
| `REDIS_URL` | Redis queue and cache URL | `redis://...` | Optional |
| `BACKEND_CORS_ORIGINS` | Permitted frontend origins | `https://your-app.vercel.app` | Yes |
| `VITE_API_BASE_URL` | API endpoint for frontend | `https://api.yourdomain.com` | Yes (Frontend) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing API key | Key string | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | Key string | Optional |
| `GOOGLE_SEARCH_API_KEY` | Google Custom Search key | Key string | Optional |
| `GOOGLE_SEARCH_ENGINE_ID` | Google CSE ID | Engine ID string | Optional |

---

## Browser Extension

PhishGuard AI Sentinel is a Manifest V3 Chromium extension:

1. Build extension bundle:
   ```bash
   cd browser-extension
   npm ci
   npm run build
   ```
2. In Google Chrome or Chromium browser, navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in upper right).
4. Click **Load unpacked** and select the `browser-extension/dist/` directory.
5. In extension options, set the backend API URL.

---

## API Documentation

When the backend is running, explore interactive endpoints:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI Specification: `http://localhost:8000/openapi.json`

Core Endpoints:
- `POST /api/v1/scans`: Create a queued URL scan.
- `GET /api/v1/scans/{id}`: Retrieve detailed scan results with URL identity separation.
- `POST /api/v1/intelligence/analyze`: Perform full multi-modal fusion analysis.
- `GET /api/v1/intelligence/{id}`: Retrieve multi-modal assessment by scan ID.
- `GET /api/v1/health`: Real-time system health (API, DB, Redis, Model Registry).

---

## Reproducibility

PhishGuard AI provides verifiable determinism:
- Fixed random seed (`42`) used across ML preprocessing and models.
- Model input and prediction SHA-256 fingerprinting.
- Live DOM snapshot hashing detects whether target content changed between repeat scans.
- Visit `/admin/reproducibility` in the frontend dashboard to run side-by-side consistency verification.

---

## Known Limitations

- **Headless Bot Blocking**: Websites protected by aggressive anti-bot challenges (e.g. Cloudflare Turnstile, Akamai) may block headless HTTP fetches. In such cases, the system records `FETCH_FAILED` and falls back to lexical intelligence.
- **Client-Side SPA Content**: Websites requiring client-side JavaScript rendering to display form fields require Playwright headless browser mode.
- **Search Engine Index Lag**: Newly registered benign domains (< 48 hours) may return `NO_RESULT` from search providers before index ingestion.

--

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for branch policies, code quality standards, and pull request requirements.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

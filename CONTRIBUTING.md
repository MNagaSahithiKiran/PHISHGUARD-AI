# Contributing to PhishGuard AI

Thank you for your interest in contributing to **PhishGuard AI** (*Intelligent Phishing Website Detection Using Artificial Intelligence*).

As a security-sensitive, multi-modal detection platform, we maintain strict standards for code quality, deterministic data lineage, automated testing, and zero-leakage security policies.

---

## 1. Development Setup

### Prerequisites
- **Python**: 3.11+
- **Node.js**: 20.x+
- **Docker & Docker Compose** (Optional, for full containerized stack)
- **Git**

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/MNagaSahithiKiran/PHISHGUARD-AI.git
cd PHISHGUARD-AI

# Create virtual environment
python -m venv .venv
# Activate on Windows:
.venv\Scripts\activate
# Activate on Unix/macOS:
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt
pip install pytest pytest-asyncio httpx alembic redis numpy

# Copy environment template
cp .env.example .env
```

### Frontend Setup
```bash
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

### Browser Extension Setup
```bash
cd browser-extension
npm ci
npm run build
```

---

## 2. Branching & Workflow Policy

- `main`: Production-ready branch. Direct pushes to `main` are restricted.
- Feature branches: `feat/<feature-name>`
- Bug fix branches: `fix/<issue-description>`
- Security branches: `sec/<security-enhancement>`

---

## 3. Testing Requirements

All contributions must pass all test suites before submitting a pull request:

```bash
# 1. Backend Pytest Suite (must pass 100%)
cd backend
python -m pytest tests/ -v

# 2. Frontend Production Build & Typecheck
cd ../frontend
npm run build

# 3. Browser Extension Tests & Build
cd ../browser-extension
npm test
npm run build

# 4. Secret & Dependency Audits
python ../backend/scripts/scan_secrets.py
python ../backend/scripts/audit_dependencies.py
```

---

## 4. Code Standards & Data Integrity Principles

1. **Zero Fake Predictions**: Never fabricate or hardcode probabilities, reputation results, or mock metrics.
2. **Explicit Fallback States**: When an external service or modality is unavailable, return documented states (`NOT_CONFIGURED`, `NOT_AVAILABLE`, `DNS_FAILED`, `INSUFFICIENT_EVIDENCE`).
3. **Deterministic Canonicalization**: Always use `normalize_url()` before storing or evaluating targets.
4. **URL Identity Separation**: Always preserve raw `original_url`, `normalized_url`, `final_url` (post-redirect), and `canonical_url` separately.
5. **No Cross-Scan Contamination**: Queries must always filter strictly by `scan_id`. Never query by URL with `ORDER BY created_at DESC LIMIT 1`.
6. **No Secrets in Commits**: Never commit actual API keys, private keys, or credentials.

---

## 5. Pull Request Guidelines

1. Ensure all CI checks pass.
2. Update relevant technical documentation in `docs/` if modifying features, APIs, or data schemas.
3. Write clean, descriptive commit messages conforming to Conventional Commits:
   - `feat: add passive TLS SAN analyzer`
   - `fix: correct redirect loop handling in HTTP analyzer`
   - `docs: update external threat intelligence reference`
4. Submit PR against `main`.

---

## 6. Reporting Security Vulnerabilities

Please do **NOT** report security vulnerabilities via public GitHub issues. Follow the guidelines in [SECURITY.md](SECURITY.md).

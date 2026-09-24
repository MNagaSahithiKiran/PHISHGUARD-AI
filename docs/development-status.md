# PhishGuard AI — Development Status & Engineering Log

**Product:** PhishGuard AI  
**Release Version:** v1.0.0 (Production Core)  
**Last Updated:** September 2026  

---

## 1. Summary of Changes

### Fixed Items
1. **Frontend-to-Backend Port Discrepancy**:
   - Replaced hardcoded `localhost:8000` references in `frontend/.env` with dynamic base resolution targeting `http://localhost:8080/api/v1`.
   - Updated `frontend/src/services/api.ts` with `getApiBaseUrl()` supporting environment variables (`VITE_API_BASE_URL`), browser origin detection, and relative proxy routing.
2. **Model Transparency Endpoint Reachability**:
   - Added `@router.get("")` and `@router.get("/")` route aliases in `backend/app/api/routes/models.py` so both `/api/v1/models` and `/api/v1/models/transparency` respond cleanly.
   - Added interactive `Retry Connection` UX in `ModelTransparency.tsx` with error diagnostics.
3. **Frontend Vite Dev Proxy**:
   - Configured `proxy` in `frontend/vite.config.ts` targeting `http://localhost:8080` for transparent local development without CORS complications.
4. **CORS Regex for Vercel Deployments**:
   - Configured `allow_origin_regex=r"^https:\/\/.*\.vercel\.app$"` in `backend/app/main.py` enabling instant preview deployments from Vercel branches.

---

### Improved Items
1. **Error Handling & Resilience**:
   - Transformed raw network errors ("Failed to fetch") into descriptive, actionable security engine messages instructing the operator on backend connectivity and retry status.
2. **UI Navigation Consistency**:
   - Updated Sidebar navigation links from academic labels ("About & IEEE Spec") to clean architectural labels ("About & Architecture").
   - Refactored `About.tsx` into a high-level system architecture overview detailing the 4-stage pipeline (SSRF Guard, Lexical Extractor, Isolated Crawling, Multi-Modal Fusion).
   - Standardized `Scanner.tsx` and `ScanResult.tsx` banner and model headers to production naming standards ("URL Intelligence Model", "Multi-Modal Fusion Engine", "Enterprise Defense Mode").
3. **Environment Template Files**:
   - Provided documented configuration in `.env.example`, `.env.development.example`, `.env.production.example`, and `frontend/.env.example`.

---

### Removed Items
1. **Academic Documentation & Papers**:
   - Removed `docs/final/` containing all IEEE paper LaTeX sources (`.tex`), bibliography files (`.bib`), thesis chapters, academic presentation slides, and viva Q&A sheets.
   - Removed `docs/final-audit/` temporary audit notes.
2. **Marketing & Spec Badges**:
   - Removed unverified UI badges such as `IEEE Spec Compliance` and `Research Standard: Zero Domain Leakage` from public views, replacing them with accurate engineering descriptions.

---

### Remaining Items & Future Roadmap
1. **Continuous Threat Feeds Integration**:
   - Webhook ingress for automated streaming ingestion of zero-day phishing feeds (URLhaus, OpenPhish).
2. **Distributed Celery / Redis Workers**:
   - Migration of background headless browser workers from in-memory queues to horizontal Celery clusters for high-volume enterprise throughput (> 5,000 scans/min).
3. **Browser Extension Web Store Publishing**:
   - Package ready-built Chrome Manifest V3 `.zip` bundle for Chrome Web Store and Edge Add-ons marketplace review.

---

## 2. Deployment Status

| Deployment Target | Readiness | Configuration Files | Validation Status |
|:---|:---:|:---|:---|
| **Local Machine** | **100% READY** | `backend/.env`, `frontend/.env`, SQLite DB | Tested & verified on port `8080` (API) and `5173` (Frontend) |
| **Vercel (Frontend)** | **100% READY** | `frontend/vercel.json`, `vercel.json` | Tested rewrite rules, SPA client-side fallback verified |
| **Backend Cloud (Render / Railway / AWS EC2)** | **100% READY** | `docker/Dockerfile.backend`, `requirements.txt` | Standardized ASGI entry point `uvicorn app.main:app` |
| **Docker Compose** | **100% READY** | `docker-compose.yml`, `Dockerfile.backend`, `Dockerfile.frontend` | Multi-container setup with PostgreSQL and Redis service blocks |
| **GitHub Actions (CI/CD)** | **100% READY** | `.github/workflows/ci.yml` | Automated pytest (62 tests), Vitest (21 tests), and bundle checks |

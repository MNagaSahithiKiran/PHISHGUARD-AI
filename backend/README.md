# PhishGuard AI - Backend Engine

The backend API service for **PhishGuard AI** provides high-performance website intake, SSRF defense, lexical feature extraction, database persistence, and extensible hooks for deep multi-modal analysis.

## Key Architecture & Features

- **FastAPI Framework**: High-throughput asynchronous routing and automatic OpenAPI documentation.
- **SQLAlchemy 2.0**: Modern async ORM supporting PostgreSQL (production) and SQLite (zero-config dev/test).
- **SSRF Barrier**: Multi-layered defense validating schemes, resolving DNS records, and actively blocking loopback, private IPv4 (RFC 1918), link-local, and cloud metadata IPs before outbound contact.
- **Zero Fake AI Metrics**: Accurately queues scans with status `queued` and `unrated` verdict until ML inference is integrated.
- **Lexical Extraction Engine**: Calculates 14+ lexical features (Shannon entropy, dot count, subdomain hierarchy, obfuscation tokens).

## API Endpoints

- `GET /`: API operational status and metadata.
- `GET /api/v1/health`: System health and database connectivity.
- `POST /api/v1/scans`: Ingest target URL, enforce SSRF guardrails, queue scan.
- `GET /api/v1/scans`: Paginated historical scans.
- `GET /api/v1/scans/stats`: Dashboard summary counts.
- `GET /api/v1/scans/{scan_id}`: Full scan details with lexical features and threat indicators.

## Running Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run API server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# 3. Run test suite
pytest -v
```

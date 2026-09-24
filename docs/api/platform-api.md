# PhishGuard AI — Platform API Specification

## Base URL
```
http://localhost:8000/api/v1
```

All API endpoints follow REST conventions and return JSON responses unless otherwise noted.

---

## 1. Authentication Endpoints (`/auth`)

### `POST /auth/register`
Creates a new analyst account.
- **Request Body**:
  ```json
  {
    "email": "analyst@phishguard.ai",
    "password": "SecurePassword123!",
    "full_name": "Security Analyst",
    "role": "user"
  }
  ```
- **Responses**:
  - `201 Created`: Returns signed JWT `access_token` and user profile.
  - `400 Bad Request`: Password shorter than 8 characters.
  - `409 Conflict`: Email already exists.

### `POST /auth/login`
Authenticates user credentials.
- **Request Body**:
  ```json
  {
    "email": "analyst@phishguard.ai",
    "password": "SecurePassword123!"
  }
  ```
- **Responses**:
  - `200 OK`: Returns JWT `access_token` and user profile.
  - `401 Unauthorized`: Invalid credentials.
  - `403 Forbidden`: Account deactivated.

### `GET /auth/me`
Retrieves currently authenticated user profile.
- **Headers**: `Authorization: Bearer <token>`
- **Responses**: `200 OK`.

### `PUT /auth/profile`
Updates full name or modifies account password.
- **Headers**: `Authorization: Bearer <token>`
- **Responses**: `200 OK`.

---

## 2. Scan & Report Endpoints (`/scans`)

### `POST /scans`
Submits target URL for automated intake and SSRF verification.
- **Request Body**: `{"url": "https://example.com"}`
- **Responses**: `201 Created` with `scan_id` and initial status `queued`.

### `GET /scans`
Retrieves paginated, searchable scan history.
- **Query Parameters**: `page`, `limit`, `status`, `verdict`, `search`.
- **Responses**: `200 OK`.

### `GET /scans/{scan_id}`
Retrieves complete scan details, lexical indicators, and domain info.

### `GET /scans/{scan_id}/report.pdf`
Generates and streams publication-grade vector PDF report.
- **Content-Type**: `application/pdf`
- **Content-Disposition**: `attachment; filename="phishguard-report-....pdf"`

### `GET /scans/export/csv`
Streams RFC 4180 compliant CSV of recorded scans.
- **Content-Type**: `text/csv`

---

## 3. Analytics & Threat Intel Endpoints

### `GET /analytics/overview`
Returns real SQL aggregations across scans, verdicts, and risk distribution bins.

### `GET /analytics/trends?days=7`
Returns daily scan volume and threat count trends.

### `GET /threat-intel/indicators`
Returns empirical frequency ranking of triggered heuristic threat indicators.

### `GET /threat-intel/domains`
Returns top targeted and scanned root domains with average risk scores.

### `GET /models/transparency`
Returns formal IEEE Model Cards for all production models.

---

## 4. Administrative Endpoints (`/admin`)
*Requires `role: admin` bearer token authorization.*

### `GET /admin/users`
Lists all registered users with their scan counts.

### `PATCH /admin/users/{user_id}/status`
Activates or deactivates an analyst account.

### `PATCH /admin/users/{user_id}/role`
Updates an analyst's role (`user` or `admin`).

### `GET /admin/audit-logs`
Queries paginated security audit trails.

### `GET /admin/system/health`
Returns deep health diagnostics: DB latency, model artifact presence, and storage checks.

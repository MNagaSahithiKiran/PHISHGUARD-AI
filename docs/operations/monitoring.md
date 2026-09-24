# Monitoring, Observability & Health Checking

## 1. Overview
PhishGuard AI provides comprehensive health checking and structured logging capabilities designed for integration with enterprise monitoring platforms (Prometheus, Grafana, Datadog, ELK).

---

## 2. Health Checking Endpoints

### 2.1 Basic Health (`GET /api/v1/health`)
* Intended for simple load balancer pings.
* Returns overall platform status, environment, and database connectivity.

### 2.2 Liveness Probe (`GET /api/v1/health/live`)
* Intended for Kubernetes / Docker container liveness checks.
* Validates that the Python ASGI event loop is active and accepting requests.
* Response: `{"status": "alive", "version": "1.0.0-phase8", "environment": "production"}`

### 2.3 Readiness Probe (`GET /api/v1/health/ready`)
* Intended for service mesh and load balancer readiness.
* Deeply inspects core infrastructure dependencies:
  1. **Database**: Executes `SELECT 1` ping.
  2. **Job Queue**: Inspects Redis or in-memory queue status and pending job counts.
  3. **Model Registry**: Validates that pre-trained AI model artifacts exist and feature version hashes match.
* Returns HTTP 200 when all subsystems are operational; returns HTTP 503 Service Unavailable if a critical component fails.

---

## 3. Structured JSON Logging & Correlation IDs
In production (`LOG_FORMAT=json`), every log line is emitted as a single-line JSON object:

```json
{
  "timestamp": "2026-09-23T23:25:00Z",
  "level": "INFO",
  "correlation_id": "c8a4911f-506e-49b2-92fc-93fba27d9ef1",
  "logger": "phishguard",
  "message": "Enqueued scan job job_scan-001 for target 'https://example.com'",
  "file": "job_queue.py:78"
}
```

* **Correlation IDs**: Stamped onto outgoing HTTP responses as `X-Correlation-ID` and `X-Request-ID`.
* **Secret Scrubbing**: Automatic redacting of sensitive patterns (`password`, `token`, `secret`, `authorization`).

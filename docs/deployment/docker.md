# Docker Architecture & Container Hardening

## 1. Multi-Stage Container Design
PhishGuard AI employs multi-stage Docker builds to achieve minimal attack surfaces and prevent build-time tools (compilers, package managers) from residing in production runtime images.

### Backend Container (`docker/Dockerfile.backend`)
* Base: `python:3.11-slim`
* User: `phishguard` (UID 10001, GID 10001) — unprivileged non-root user.
* Security: No root execution, write permissions limited exclusively to `/app/storage`.
* Healthcheck: `curl -f http://localhost:8000/api/v1/health/live || exit 1`

### Frontend Container (`docker/Dockerfile.frontend`)
* Stage 1: `node:20-alpine` executes `npm run build` producing static SPA bundle.
* Stage 2: `nginx:1.25-alpine` serves static assets with Brotli/Gzip and security headers.
* Permissions: Non-root user ownership of runtime PID and cache paths.

### Sandboxed Worker Container (`docker/Dockerfile.worker`)
* Base: `mcr.microsoft.com/playwright/python:v1.40.0-jammy`
* User: `pwuser` (dedicated browser sandbox user).
* Isolation Boundary: Headless Chromium executes with `--disable-gpu`, `--no-sandbox` (controlled within container namespace), with network egress filtered through SSRF pre-flight validation.

---

## 2. Container Resource Quotas

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 2G
    reservations:
      cpus: '0.5'
      memory: 512M
```
Resource limits prevent compromised or memory-leaking crawler pages from causing host starvation.

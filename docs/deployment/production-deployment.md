# Production Deployment Guide

## 1. Executive Summary
This document provides production guidelines for deploying **PhishGuard AI** (*"Detect. Explain. Protect."*) into production cloud and on-premise environments.

---

## 2. Infrastructure Requirements

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **CPU** | 4 Cores (x86_64) | 8 Cores (x86_64) |
| **RAM** | 8 GB | 16 GB |
| **Storage** | 50 GB SSD (Ext4 / APFS) | 200 GB NVMe SSD |
| **OS** | Ubuntu 22.04 LTS / Debian 12 | Ubuntu 22.04 LTS / RHEL 9 |
| **Container Engine**| Docker Engine 24.0+ & Compose v2 | Docker Engine 26.0+ |

---

## 3. Configuration & Secret Management
Production configurations are strictly loaded through environment variables.
* **Fail-Fast Validation**: The backend will terminate immediately on startup if:
  1. `ENVIRONMENT=production` and `SECRET_KEY` is shorter than 32 characters or uses default placeholders.
  2. `DEBUG=true` in production.
  3. `DATABASE_URL` specifies SQLite instead of PostgreSQL.
  4. Wildcard `*` is present in `ALLOWED_HOSTS` or `BACKEND_CORS_ORIGINS`.

---

## 4. Reverse Proxy & Network Architecture
All external incoming traffic must enter through the Nginx reverse proxy. Direct exposure of the FastAPI backend or Redis/PostgreSQL containers to the public internet is strictly forbidden.

* **Port 80**: HTTP redirect to HTTPS.
* **Port 443**: TLS 1.3 termination with strict cipher suites.
* **Rate Limiting**:
  * Global API limit: 30 requests per minute per IP.
  * Authentication login limit: 10 requests per minute per IP.

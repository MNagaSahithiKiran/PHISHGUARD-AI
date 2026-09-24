# PhishGuard AI - Production Deployment & Operations Manual

## 1. Overview
This manual provides operational instructions for deploying **PhishGuard AI** across containerized environments (Docker Compose, Kubernetes, and Cloud Virtual Machines).

---

## 2. Architecture & Service Topology

```
                  Internet / Browser Clients
                              │
                              ▼
            ┌───────────────────────────────────┐
            │       Nginx Reverse Proxy         │
            │   TLS Termination (Port 443/80)   │
            │  Global Rate Limiting & SecHeaders│
            └───────────────┬───────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐       ┌───────────────────────┐
│     Frontend SPA      │       │     Backend API       │
│   (Nginx Alpine :80)  │       │ (FastAPI Uvicorn :8000)│
└───────────────────────┘       └───────────┬───────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │   Redis Queue (:6379) │
                                └───────────┬───────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │   Playwright Worker   │
                                │  Sandboxed Rendering  │
                                └───────────┬───────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │ PostgreSQL 16 (:5432) │
                                │   Connection Pooled   │
                                └───────────────────────┘
```

---

## 3. Production Deployment with Docker Compose

### Step 1: Prepare Environment Secrets
1. Copy the production environment template:
   ```bash
   cp .env.production.example .env
   ```
2. Generate a 64-character cryptographic secret key:
   ```bash
   openssl rand -hex 32
   ```
3. Set the generated key in `.env` as `SECRET_KEY`.
4. Set strong, unique passwords for `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `ADMIN_DEFAULT_PASSWORD`.
5. Ensure `DEBUG=false` and `ENVIRONMENT=production`.

### Step 2: Build and Launch Containers
```bash
docker-compose -f docker-compose.yml up --build -d
```

### Step 3: Run Alembic Database Migrations
```bash
docker-compose exec backend python scripts/migrate.py
```

### Step 4: Verify Service Health
```bash
# Check liveness
curl http://localhost/health

# Check full readiness (Database, Redis, Model Registry)
curl http://localhost/api/v1/health/ready
```

---

## 4. Database Backup & Restore

### Automated Nightly Backup (Cron)
Add the following entry to your host crontab (`crontab -e`):
```cron
0 2 * * * /opt/phishguard-ai/deployment/scripts/backup.sh >> /var/log/phishguard_backup.log 2>&1
```

### Manual Backup Command
```bash
./deployment/scripts/backup.sh
```

### Restore Procedure
```bash
./deployment/scripts/restore.sh /var/backups/phishguard/phishguard_phishguard_db_20260923_020000.dump
```

---

## 5. Security & TLS Hardening
* **TLS Termination**: Place valid certificates in `/etc/ssl/certs/phishguard.crt` and `/etc/ssl/private/phishguard.key`.
* **HSTS**: Strict Transport Security is enabled automatically when `ENVIRONMENT=production`.
* **Private Network Isolation**: PostgreSQL and Redis are bound exclusively to the internal bridge network `phishguard-backend-net` and have no exposed host ports in production.

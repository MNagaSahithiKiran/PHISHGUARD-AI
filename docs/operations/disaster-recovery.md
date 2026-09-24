# Disaster Recovery Plan & Business Continuity

## 1. Objectives & Metrics
* **Recovery Point Objective (RPO)**: $\le 24\text{ hours}$ for standard backups; $\le 15\text{ minutes}$ with WAL streaming enabled.
* **Recovery Time Objective (RTO)**: $\le 60\text{ minutes}$ to restore the complete containerized stack on fresh hardware.

---

## 2. Disaster Scenarios & Playbooks

### Scenario A: Database Corruption or Volume Loss
1. Provision a clean PostgreSQL 16 container or managed instance.
2. Locate the most recent valid backup in the backup storage bucket.
3. Execute the restoration script:
   ```bash
   ./deployment/scripts/restore.sh /var/backups/phishguard/latest_valid.dump
   ```
4. Run Alembic schema verification:
   ```bash
   python backend/scripts/migrate.py
   ```
5. Confirm application readiness via `curl http://localhost/api/v1/health/ready`.

### Scenario B: Complete Host / VM Failure
1. Clone the repository to the replacement host:
   ```bash
   git clone <repo_url> /opt/phishguard-ai
   cd /opt/phishguard-ai
   ```
2. Pull production secrets from the corporate secret store (Vault / AWS Secrets Manager) into `.env`.
3. Launch container infrastructure:
   ```bash
   docker-compose up -d --build
   ```
4. Restore database from the off-site backup.
5. Rebuild and distribute the browser extension if needed:
   ```bash
   cd browser-extension && npm ci && npm run build
   ```

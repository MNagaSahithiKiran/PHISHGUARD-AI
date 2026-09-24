# Database Backup Strategy & Operations

## 1. Backup Strategy Overview
PhishGuard AI requires a strict backup policy to ensure zero data loss of threat intelligence indicators, user accounts, and scan audit logs.

| Backup Type | Frequency | Tool / Mechanism | Retention Period |
| :--- | :--- | :--- | :--- |
| **Full Snapshot** | Daily at 02:00 UTC | `pg_dump -F c` (Binary compressed) | 14 Days |
| **Weekly Archive** | Sunday at 03:00 UTC | Compressed tarball to cold storage | 90 Days |
| **Point-in-Time (PITR)**| Continuous | PostgreSQL WAL Archiving | 7 Days |

---

## 2. Backup Execution
Automated backups are handled by `deployment/scripts/backup.sh`.
Features:
* Binary custom format (`-F c`) allowing parallel restoration and table filtering.
* Automatic Gzip compression.
* Automated timestamping: `phishguard_phishguard_db_YYYYMMDD_HHMMSS.dump`.
* Retention pruning: Deletes dumps older than `RETENTION_DAYS` (default 14 days).

### Manual Backup Command
```bash
./deployment/scripts/backup.sh
```

---

## 3. Database Restoration
Database recovery is executed using `deployment/scripts/restore.sh`:

```bash
./deployment/scripts/restore.sh /var/backups/phishguard/phishguard_phishguard_db_20260923_020000.dump
```

Safety Controls:
* Restores schema and data cleanly using `pg_restore --clean --if-exists`.
* Requires explicit typed user confirmation (`RESTORE`) to prevent accidental destruction of production data.

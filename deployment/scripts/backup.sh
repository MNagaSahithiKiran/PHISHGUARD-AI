#!/usr/bin/env bash
# ==============================================================================
# PhishGuard AI - Automated PostgreSQL Backup Script
# Generates a compressed pg_dump snapshot with timestamping and retention pruning.
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/phishguard}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-phishguard}"
POSTGRES_DB="${POSTGRES_DB:-phishguard_db}"

mkdir -p "${BACKUP_DIR}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/phishguard_${POSTGRES_DB}_${TIMESTAMP}.dump"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting automated database backup for '${POSTGRES_DB}'..."

# Execute binary pg_dump (custom format with compression)
PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_dump \
  -h "${POSTGRES_HOST}" \
  -p "${POSTGRES_PORT}" \
  -U "${POSTGRES_USER}" \
  -F c \
  -b \
  -v \
  -f "${BACKUP_FILE}" \
  "${POSTGRES_DB}"

FILE_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Backup successfully written: ${BACKUP_FILE} (${FILE_SIZE})"

# Prune backups older than retention window
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Pruning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -name "phishguard_${POSTGRES_DB}_*.dump" -mtime +"${RETENTION_DAYS}" -delete

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Backup job completed successfully."

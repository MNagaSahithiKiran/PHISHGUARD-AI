#!/usr/bin/env bash
# ==============================================================================
# PhishGuard AI - PostgreSQL Database Restore Utility
# Restores a binary pg_dump snapshot into a clean database.
# ==============================================================================

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path_to_backup_file.dump>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file '${BACKUP_FILE}' does not exist!"
    exit 1
fi

POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-phishguard}"
POSTGRES_DB="${POSTGRES_DB:-phishguard_db}"

echo "======================================================================"
echo "WARNING: Restoring will overwrite existing data in '${POSTGRES_DB}'!"
echo "Target host: ${POSTGRES_HOST}:${POSTGRES_PORT}"
echo "Backup file: ${BACKUP_FILE}"
echo "======================================================================"

read -p "Type 'RESTORE' to confirm and proceed: " CONFIRMATION
if [ "${CONFIRMATION}" != "RESTORE" ]; then
    echo "Restore aborted by user."
    exit 0
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Executing pg_restore..."

PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_restore \
  -h "${POSTGRES_HOST}" \
  -p "${POSTGRES_PORT}" \
  -U "${POSTGRES_USER}" \
  -d "${POSTGRES_DB}" \
  --clean \
  --if-exists \
  -v \
  "${BACKUP_FILE}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Database restoration completed successfully."

#!/usr/bin/env bash
# ─── ComplianceFlow AI: Automated PostgreSQL Backup Script ───
# Dumps full PostgreSQL database (tenants, jobs, audit trail) to compressed SQL file

set -e

BACKUP_DIR="${HOME}/db_backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/compflow_db_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "=== [1/2] Creating PostgreSQL Dump from compflow-postgres container ==="
sudo docker exec compflow-postgres pg_dump -U compflow_user -d compflow | gzip > "${BACKUP_FILE}"

echo "=== [2/2] Backup Complete! ==="
echo "File created: ${BACKUP_FILE}"
ls -lh "${BACKUP_FILE}"

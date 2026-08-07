#!/usr/bin/env bash
# ─── ComplianceFlow AI: Database Restore Script ───
# Restores a compressed SQL dump file into the compflow-postgres container

set -e

FILE="$1"

if [ -z "$FILE" ]; then
    echo "Usage: ./restore_db.sh <path_to_sql.gz_file>"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "Error: File $FILE not found."
    exit 1
fi

echo "=== [1/2] Restoring PostgreSQL database from ${FILE} ==="
zcat "$FILE" | sudo docker exec -i compflow-postgres psql -U compflow_user -d compflow

echo "=== [2/2] Restore Complete! All tenants, jobs, and data successfully loaded. ==="

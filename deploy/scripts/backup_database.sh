#!/usr/bin/env bash
set -euo pipefail

MYSQLDUMP_BIN="${MYSQLDUMP_BIN:-mysqldump}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-office_asset_app}"
DB_NAME="${DB_NAME:-office_asset_mgmt}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/office-asset-mgmt}"

if [[ -z "${MYSQL_PWD:-}" ]]; then
  read -r -s -p "MySQL password for ${DB_USER}: " MYSQL_PWD
  echo
  export MYSQL_PWD
fi

mkdir -p "${BACKUP_DIR}"
backup_file="${BACKUP_DIR}/${DB_NAME}_$(date +%Y%m%d_%H%M%S).sql"

"${MYSQLDUMP_BIN}" \
  --host="${DB_HOST}" \
  --port="${DB_PORT}" \
  --user="${DB_USER}" \
  --single-transaction \
  --routines \
  --events \
  --triggers \
  --default-character-set=utf8mb4 \
  "${DB_NAME}" > "${backup_file}"

chmod 600 "${backup_file}"
echo "Backup written to ${backup_file}"

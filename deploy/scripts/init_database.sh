#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MYSQL_BIN="${MYSQL_BIN:-mysql}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-root}"
DB_NAME="${DB_NAME:-office_asset_mgmt}"

if [[ -z "${MYSQL_PWD:-}" ]]; then
  read -r -s -p "MySQL password for ${DB_USER}: " MYSQL_PWD
  echo
  export MYSQL_PWD
fi

mysql_args=(
  "--host=${DB_HOST}"
  "--port=${DB_PORT}"
  "--user=${DB_USER}"
  "--default-character-set=utf8mb4"
)

if [[ ! "${DB_NAME}" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "DB_NAME must contain only letters, numbers, and underscores." >&2
  exit 1
fi

"${MYSQL_BIN}" "${mysql_args[@]}" \
  -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

for sql_file in \
  01_schema.sql \
  02_seed_reference_data.sql \
  03_views.sql \
  04_routines.sql \
  10_audit_log.sql \
  12_it_inventory.sql \
  13_hardening_migration.sql \
  14_computer_configuration.sql \
  15_inventory_computer_batches.sql \
  16_inventory_purchase_log.sql \
  17_data_lineage_and_consistency.sql \
  18_backfill_computer_inbound_dates.sql \
  19_auth_and_settings.sql \
  20_database_backup.sql \
  21_security_hardening.sql \
  22_update_repository_setting.sql
do
  echo "Applying ${sql_file}"
  "${MYSQL_BIN}" "${mysql_args[@]}" "${DB_NAME}" < "${ROOT_DIR}/database/${sql_file}"
done

echo "Database initialization completed: ${DB_NAME}"

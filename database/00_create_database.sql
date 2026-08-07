-- Office asset management database.
-- Target: MySQL 8.0.16+
-- This compatibility helper creates the default database only. Production
-- initialization should use deploy/scripts/init_database.sh, which validates
-- DB_NAME and selects the requested database explicitly.

CREATE DATABASE IF NOT EXISTS office_asset_mgmt
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

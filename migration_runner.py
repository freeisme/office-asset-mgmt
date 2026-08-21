from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
MIGRATIONS_DIR = ROOT_DIR / "migrations"
HISTORICAL_FIXED_USE_MIGRATIONS = {
    "20260814_001_itil_governance",
    "20260814_002_command_atomicity",
}


@dataclass(frozen=True)
class Migration:
    version: str
    path: Path
    checksum: str


def mysql_args(database: str) -> list[str]:
    mysql_bin = os.environ.get("MYSQL_BIN", r"D:\MYSQL\bin\mysql.exe")
    host = os.environ.get("DB_HOST", "127.0.0.1")
    port = os.environ.get("DB_PORT", "3306")
    user = os.environ.get("DB_USER", "root")
    return [
        mysql_bin,
        "--protocol=tcp",
        f"--host={host}",
        f"--port={port}",
        f"--user={user}",
        f"--database={database}",
        "--default-character-set=utf8mb4",
        "--batch",
        "--raw",
        "--skip-column-names",
        "--silent",
    ]


def run_mysql(sql: str, database: str) -> str:
    env = os.environ.copy()
    password = env.get("DB_PASSWORD", "")
    if not password:
        raise RuntimeError("DB_PASSWORD environment variable is required.")
    env["MYSQL_PWD"] = password
    completed = subprocess.run(
        mysql_args(database),
        input=sql,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(ROOT_DIR),
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "Unknown MySQL error"
        raise RuntimeError(message)
    return completed.stdout.strip()


def sql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def ensure_registry(database: str) -> None:
    run_mysql(
        """
        CREATE TABLE IF NOT EXISTS schema_migration (
          version VARCHAR(128) NOT NULL,
          checksum_sha256 CHAR(64) NOT NULL,
          description VARCHAR(255) NOT NULL DEFAULT '',
          applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          applied_by VARCHAR(128) NOT NULL DEFAULT '',
          PRIMARY KEY (version)
        ) ENGINE=InnoDB;
        """,
        database,
    )


def table_exists(database: str, table_name: str) -> bool:
    result = run_mysql(
        f"""
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = {sql_quote(table_name)};
        """,
        database,
    )
    return result == "1"


def has_existing_business_tables(database: str) -> bool:
    result = run_mysql(
        """
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name IN ('org_unit', 'employee', 'computer_asset');
        """,
        database,
    )
    return int(result or "0") > 0


def discover_migrations() -> list[Migration]:
    if not MIGRATIONS_DIR.exists():
        return []
    migrations: list[Migration] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        content = path.read_bytes()
        migrations.append(
            Migration(
                version=path.stem,
                path=path,
                checksum=hashlib.sha256(content).hexdigest(),
            )
        )
    return migrations


def applied_migrations(database: str) -> dict[str, str]:
    output = run_mysql("SELECT version, checksum_sha256 FROM schema_migration ORDER BY version;", database)
    records: dict[str, str] = {}
    for line in output.splitlines():
        version, _, checksum = line.partition("\t")
        if version:
            records[version] = checksum
    return records


def mark_baseline(database: str, version: str) -> None:
    checksum = hashlib.sha256(version.encode("utf-8")).hexdigest()
    run_mysql(
        f"""
        INSERT INTO schema_migration (version, checksum_sha256, description, applied_by)
        VALUES (
          {sql_quote(version)},
          {sql_quote(checksum)},
          'Historical schema baseline recorded by deployment',
          {sql_quote(os.environ.get('USERNAME', 'deployment'))}
        )
        ON DUPLICATE KEY UPDATE version = VALUES(version);
        """,
        database,
    )
    print(f"Baseline recorded: {version}")


def apply_migrations(database: str, verify_only: bool = False) -> None:
    existing = applied_migrations(database)
    for migration in discover_migrations():
        current_checksum = existing.get(migration.version)
        if current_checksum:
            if current_checksum != migration.checksum:
                raise RuntimeError(
                    f"Migration checksum mismatch for {migration.version}. "
                    "Create a new migration instead of editing an applied file."
                )
            print(f"Verified: {migration.version}")
            continue
        if verify_only:
            print(f"Pending: {migration.version}")
            continue

        sql = migration.path.read_text(encoding="utf-8")
        fixed_use = re.compile(r"^\s*USE\s+[^;]+;\s*", flags=re.IGNORECASE | re.MULTILINE)
        if fixed_use.search(sql):
            if migration.version not in HISTORICAL_FIXED_USE_MIGRATIONS:
                raise RuntimeError(
                    f"Migration {migration.version} contains a fixed USE statement. "
                    "Migrations must run against the database selected by --database."
                )
            sql = fixed_use.sub("", sql, count=1)
            print(
                f"Compatibility mode: removed the historical fixed USE statement "
                f"from {migration.version} before execution."
            )
        print(f"Applying: {migration.version}")
        run_mysql(sql, database)
        run_mysql(
            f"""
            INSERT INTO schema_migration (version, checksum_sha256, description, applied_by)
            VALUES (
              {sql_quote(migration.version)},
              {sql_quote(migration.checksum)},
              {sql_quote(migration.path.name)},
              {sql_quote(os.environ.get('USERNAME', 'deployment'))}
            );
            """,
            database,
        )
    if verify_only:
        pending = [item.version for item in discover_migrations() if item.version not in existing]
        if pending:
            raise RuntimeError("Pending migrations: " + ", ".join(pending))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply tracked MySQL migrations.")
    parser.add_argument("--database", default=os.environ.get("DB_NAME", "office_asset_mgmt"))
    parser.add_argument("--mark-baseline", default="")
    parser.add_argument("--verify", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        registry_exists = table_exists(args.database, "schema_migration")
        if not registry_exists and has_existing_business_tables(args.database) and not args.mark_baseline:
            raise RuntimeError(
                "This database has business tables but no schema_migration registry. "
                "Take a verified backup, confirm the legacy baseline, then run with "
                "--mark-baseline legacy-20260813."
            )
        ensure_registry(args.database)
        if args.mark_baseline:
            mark_baseline(args.database, args.mark_baseline)
        apply_migrations(args.database, verify_only=args.verify)
    except RuntimeError as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

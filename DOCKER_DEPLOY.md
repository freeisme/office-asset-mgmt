# Docker Deployment

This document deploys the data-free release of Office Asset Management with Docker Compose.
The stack contains:

```text
Browser
  |
  +-- app:8000 (Python HTTP service)
          |
          +-- db:3306 (MySQL 8.4, internal Compose network only)
```

The MySQL data is stored in the named Docker volume `mysql-data`; web-created database
backups are stored separately in `backup-data`. The database port is not published to the
host by default.

## 1. Prerequisites

Install Docker Engine or Docker Desktop with Docker Compose v2, then verify:

```bash
docker --version
docker compose version
```

On Ubuntu, run the commands below as a user that is allowed to use Docker.

## 2. Configure Secrets

From the project root:

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and replace both passwords before the first startup:

```dotenv
APP_PORT=8000
DB_NAME=office_asset_mgmt
DB_USER=office_asset_app
DB_PASSWORD=replace-with-a-long-random-password
MYSQL_ROOT_PASSWORD=replace-with-a-different-long-random-password
AUTH_SESSION_HOURS=8
AUTH_COOKIE_SECURE=false
```

Rules:

- `DB_PASSWORD` is the application database account password.
- `MYSQL_ROOT_PASSWORD` is only for MySQL administration and must differ from `DB_PASSWORD`.
- Do not commit `.env` to Git.
- Keep `AUTH_COOKIE_SECURE=false` only when accessing the system by HTTP. Set it to
  `true` after HTTPS is configured through a reverse proxy.

## 3. First Startup

Run:

```bash
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs -f
```

The first start initializes MySQL and runs every SQL file in `database/` in numeric order.
This creates schema and reference data only; it does not import business data.

Verify the services:

```bash
curl http://127.0.0.1:8000/api/health
docker compose exec db sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SHOW TABLES;"'
```

Open the application:

```text
http://SERVER_IP:8000/
```

The first browser visit opens the administrator initialization page. The system has no
fixed default password.

## 4. LAN and Reverse Proxy

For direct LAN access, keep:

```dotenv
APP_PORT=8000
```

Then allow TCP port 8000 only for the required LAN network.

For Nginx on the same host, bind the application to loopback instead:

```dotenv
APP_PORT=127.0.0.1:8000
AUTH_COOKIE_SECURE=true
```

Use the existing Nginx example at `deploy/nginx/office-asset-mgmt.conf` and expose only
ports 80/443. Do not publish MySQL port 3306 unless a separate operational requirement
exists.

## 5. Data Persistence and Backup

Check the named volume:

```bash
docker volume ls
docker volume inspect office-asset-management-github_mysql-data
docker volume inspect office-asset-management-github_backup-data
```

Open **Settings > Database backup** as an administrator to create a backup immediately,
set the daily backup time, review the backup list, and download a selected backup after
confirming the current account password. Scheduled and manual web backups are compressed
`.sql.gz` files in the `backup-data` volume and are not served as static web files.

For an additional independent raw SQL backup from the command line:

```bash
mkdir -p backups
docker compose exec -T db sh -c \
  'exec mysqldump --single-transaction --routines --events --triggers -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  > "backups/office_asset_mgmt_$(date +%Y%m%d_%H%M%S).sql"
```

Restore a verified backup:

```bash
docker compose exec -T db sh -c \
  'exec mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  < backups/office_asset_mgmt_YYYYMMDD_HHMMSS.sql
```

Store backups outside the server as well. Do not commit generated `.sql` or `.sql.gz`
backup files.

## 6. Upgrade

Before updating, create a backup. Then:

```bash
git pull
docker compose build --pull app
docker compose up -d
docker compose ps
curl http://127.0.0.1:8000/api/health
```

Database scripts in `/docker-entrypoint-initdb.d` run only when the MySQL volume is empty.
For schema changes on an existing system, review the release migration notes and run the
appropriate SQL migration manually against the `db` service.

## 7. Stop and Remove

Stop containers while retaining database data:

```bash
docker compose down
```

Stop containers and permanently delete all Docker-managed database data:

```bash
docker compose down -v
```

Run the second command only after a successful backup has been verified.

## 8. Troubleshooting

```bash
docker compose ps
docker compose logs --tail=200 app
docker compose logs --tail=200 db
docker compose exec app python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health').read().decode())"
docker compose exec db sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SELECT 1;"'
```

If the database initialization was interrupted during the first startup, inspect the
database logs before deciding whether to remove `mysql-data`. Removing the volume starts
with an empty database and deletes all data stored in that volume.

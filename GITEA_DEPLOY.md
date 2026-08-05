# Private Gitea and Docker Deployment

This setup uses:

```text
Gitea + PostgreSQL
        |
        +-- private Git repositories and project management
        |
        +-- signed push webhook for main
                    |
                    +-- validate and acknowledge only
                    +-- no automatic deployment
```

The webhook receiver runs as a dedicated host service. It does not mount the Docker
socket into the Gitea container and it only accepts a valid HMAC-signed push event for
the configured repository and branch.

## 1. Server prerequisites

On an Ubuntu server, install Docker Compose v2, Git, Python, and curl:

```bash
sudo apt update
sudo apt install -y ca-certificates curl git python3
```

Install Docker Engine and the Compose plugin using the official Docker instructions.
Then verify:

```bash
docker --version
docker compose version
```

Create the application deployment account and grant it Docker access:

```bash
sudo useradd --create-home --shell /bin/bash officeasset-deploy || true
sudo usermod -aG docker officeasset-deploy
sudo mkdir -p /opt/office-asset-mgmt /opt/gitea /etc/office-asset-mgmt
sudo chown -R officeasset-deploy:officeasset-deploy /opt/office-asset-mgmt
```

Log in again after changing the Docker group membership.

## 2. Start Gitea

Copy `deploy/gitea/compose.yaml` and `deploy/gitea/.env.example` to `/opt/gitea`:

```bash
sudo cp deploy/gitea/compose.yaml /opt/gitea/compose.yaml
sudo cp deploy/gitea/.env.example /opt/gitea/.env
sudo chown -R root:root /opt/gitea
sudo chmod 600 /opt/gitea/.env
sudo nano /opt/gitea/.env
```

Set at least:

```dotenv
GITEA_DB_PASSWORD=use-a-long-random-password
GITEA_DOMAIN=git.example.com
GITEA_ROOT_URL=https://git.example.com/
GITEA_SSH_DOMAIN=git.example.com
```

For a first LAN-only installation, `GITEA_ROOT_URL` can be
`http://SERVER_IP:3000/`. Start the stack:

```bash
cd /opt/gitea
docker compose config
docker compose up -d
docker compose ps
```

Open the configured HTTP URL, create the first administrator, and create a private
repository such as `office-asset-management`. Keep registration disabled unless the
server is intentionally open to self-registration.

After the first administrator has been created, set `GITEA_INSTALL_LOCK=true` in
`/opt/gitea/.env` and restart the stack:

```bash
cd /opt/gitea
docker compose up -d
```

Expose Gitea through HTTPS when it is reachable outside a trusted LAN. Keep PostgreSQL
unpublished and allow only the Gitea HTTP/HTTPS and SSH ports through the firewall.

## 3. Push the project to Gitea

On the development machine:

```powershell
cd D:\数据库\office-asset-management-github
git init
git branch -M main
git add .
git diff --cached --check
git commit -m "Initial private repository"
git remote add origin ssh://git@GITEA_HOST:2222/OWNER/office-asset-management.git
git push -u origin main
```

Replace `GITEA_HOST`, `OWNER`, and the SSH port with the values used in
`/opt/gitea/.env`.

On the application server, clone the same repository into the deployment path:

```bash
sudo -u officeasset-deploy git clone \
  ssh://git@GITEA_HOST:2222/OWNER/office-asset-management.git \
  /opt/office-asset-mgmt
```

Create `/opt/office-asset-mgmt/.env` from the existing `env.example`, set production
database passwords, and verify the application once with:

```bash
cd /opt/office-asset-mgmt
docker compose --env-file .env up -d --build
curl --fail http://127.0.0.1:8000/api/health
```

## 4. Give the deployment account read access

Generate a key on the application server:

```bash
sudo -u officeasset-deploy mkdir -p /home/officeasset-deploy/.ssh
sudo -u officeasset-deploy ssh-keygen -t ed25519 \
  -f /home/officeasset-deploy/.ssh/id_ed25519 \
  -N "" \
  -C "officeasset-deploy"
sudo cat /home/officeasset-deploy/.ssh/id_ed25519.pub
```

Add this public key to the Gitea repository as a read-only Deploy Key. Then record the
Gitea host key and test the fetch as the deployment account:

```bash
sudo -u officeasset-deploy ssh-keyscan -p 2222 GITEA_HOST \
  >> /home/officeasset-deploy/.ssh/known_hosts
sudo chmod 700 /home/officeasset-deploy/.ssh
sudo chmod 600 /home/officeasset-deploy/.ssh/id_ed25519
sudo chmod 644 /home/officeasset-deploy/.ssh/known_hosts
sudo -u officeasset-deploy git -C /opt/office-asset-mgmt fetch origin main
```

Verify the repository's `origin` URL uses the same Gitea host and port.

## 5. Enable manual Docker deployment controls

Create a strong webhook secret:

```bash
openssl rand -hex 32
```

Create `/etc/office-asset-mgmt/gitea-webhook.env` with mode `600`:

```dotenv
GITEA_WEBHOOK_SECRET=replace-with-the-generated-secret
DEPLOY_CONTROL_TOKEN=replace-with-a-different-generated-secret
WEBHOOK_BIND=0.0.0.0
WEBHOOK_PORT=9000
WEBHOOK_PATH=/gitea
DEPLOY_REPO=OWNER/office-asset-management
DEPLOY_BRANCH=main
DEPLOY_VERSION_LIST_LIMIT=30
APP_DIR=/opt/office-asset-mgmt
```

Set the same `DEPLOY_CONTROL_TOKEN` in `/opt/office-asset-mgmt/.env` as
`UPDATE_CONTROL_TOKEN`. The application uses this separate token to read available
versions and queue a manually selected commit. It is not the Gitea webhook signature
and must not be exposed to browsers.

Install and start the receiver:

```bash
sudo cp deploy/gitea/office-asset-gitea-webhook.service \
  /etc/systemd/system/office-asset-gitea-webhook.service
sudo chmod 600 /etc/office-asset-mgmt/gitea-webhook.env
sudo systemctl daemon-reload
sudo systemctl enable --now office-asset-gitea-webhook
sudo systemctl status office-asset-gitea-webhook
curl --fail http://127.0.0.1:9000/healthz
```

In the Gitea repository, open **Settings > Webhooks > Add Webhook > Gitea** and use:

```text
Target URL: http://host.docker.internal:9000/gitea
HTTP Method: POST
POST Content Type: application/json
Secret: the same value as GITEA_WEBHOOK_SECRET
Trigger: Push Events only
Branch filter: main
Active: enabled
```

The Gitea Compose file maps `host.docker.internal` to the Docker host and allows
Webhook delivery to private addresses. Do not publish TCP port 9000 to the public
Internet; allow it only from the Docker bridge or use a firewall rule that blocks
external access.

Now a push to `main` only runs:

```text
HMAC validation -> repository/branch validation -> 204 acknowledgement
```

Administrators use **Settings > 版本更新** to check recent `main` commits, select a
newer target version, and confirm the update. The deployment service verifies that the
selected commit belongs to `origin/main` history and is not older than the current
deployment before building and restarting Docker.

Each release must add a corresponding entry to `VERSION_NOTES.md`, including database
migrations, backup requirements, configuration changes, and rollback notes.

Watch deployment logs:

```bash
sudo journalctl -u office-asset-gitea-webhook -f
docker compose -f /opt/office-asset-mgmt/compose.yaml ps
docker compose -f /opt/office-asset-mgmt/compose.yaml logs --tail=100 app
```

Database migrations are intentionally not run automatically. Back up the database and
apply a reviewed migration manually before deploying a schema-changing release.

## 6. Backup Gitea

Back up both the Gitea data volume and PostgreSQL volume. At minimum, stop writes before
copying them, or use a database-aware backup for PostgreSQL:

```bash
cd /opt/gitea
docker compose exec -T gitea-db pg_dump -U gitea gitea > gitea.sql
docker compose exec -T gitea-db pg_dumpall -U gitea --globals-only > gitea-globals.sql
```

Store these backups outside the server and protect them as sensitive data.

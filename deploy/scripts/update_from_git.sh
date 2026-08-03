#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
SERVICE_NAME="${SERVICE_NAME:-office-asset-mgmt}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/api/health}"

cd "${APP_DIR}"

if [[ ! -d .git ]]; then
  echo "Deployment directory is not a Git checkout: ${APP_DIR}" >&2
  exit 1
fi

echo "Fetching origin/${DEPLOY_BRANCH} ..."
git fetch --prune origin "${DEPLOY_BRANCH}"

if git show-ref --verify --quiet "refs/heads/${DEPLOY_BRANCH}"; then
  git checkout "${DEPLOY_BRANCH}"
else
  git checkout -b "${DEPLOY_BRANCH}" --track "origin/${DEPLOY_BRANCH}"
fi

git reset --hard "origin/${DEPLOY_BRANCH}"

echo "Restarting ${SERVICE_NAME} ..."
sudo -n systemctl restart "${SERVICE_NAME}"
sudo -n systemctl is-active --quiet "${SERVICE_NAME}"

if command -v curl >/dev/null 2>&1; then
  echo "Checking ${HEALTH_URL} ..."
  health_ok=0
  for _ in {1..10}; do
    if curl --fail --silent --show-error --max-time 15 "${HEALTH_URL}" >/dev/null; then
      health_ok=1
      break
    fi
    sleep 2
  done
  if [[ "${health_ok}" -ne 1 ]]; then
    echo "Health check failed: ${HEALTH_URL}" >&2
    exit 1
  fi
fi

echo "Published commit: $(git rev-parse --short HEAD)"

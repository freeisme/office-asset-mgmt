#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
DEPLOY_EXPECTED_SHA="${DEPLOY_EXPECTED_SHA:-}"
COMPOSE_FILE="${COMPOSE_FILE:-${APP_DIR}/compose.yaml}"
ENV_FILE="${ENV_FILE:-${APP_DIR}/.env}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/api/health}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-${APP_DIR}/.deploy.lock}"

exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  echo "Another deployment is already running; the latest push will be handled by its worker." >&2
  exit 0
fi

cd "${APP_DIR}"

if [[ ! -d .git ]]; then
  echo "Deployment directory is not a Git checkout: ${APP_DIR}" >&2
  exit 1
fi
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing runtime environment file: ${ENV_FILE}" >&2
  exit 1
fi

export GIT_TERMINAL_PROMPT=0
echo "Fetching origin/${DEPLOY_BRANCH} ..."
git fetch --prune origin "${DEPLOY_BRANCH}"

remote_sha="$(git rev-parse "origin/${DEPLOY_BRANCH}")"
if [[ -n "${DEPLOY_EXPECTED_SHA}" && "${DEPLOY_EXPECTED_SHA}" != "${remote_sha}" ]]; then
  echo "Push ${DEPLOY_EXPECTED_SHA} was superseded by ${remote_sha}; deploying the latest origin/${DEPLOY_BRANCH}."
fi

git checkout -B "${DEPLOY_BRANCH}" "origin/${DEPLOY_BRANCH}"
git reset --hard "origin/${DEPLOY_BRANCH}"

compose_args=(--env-file "${ENV_FILE}" -f "${COMPOSE_FILE}")
docker compose "${compose_args[@]}" config --quiet

echo "Building the application image ..."
docker compose "${compose_args[@]}" build --pull app

echo "Starting the application stack ..."
docker compose "${compose_args[@]}" up -d --remove-orphans

echo "Checking ${HEALTH_URL} ..."
health_ok=0
for _ in {1..30}; do
  if curl --fail --silent --show-error --max-time 10 "${HEALTH_URL}" >/dev/null; then
    health_ok=1
    break
  fi
  sleep 2
done

if [[ "${health_ok}" -ne 1 ]]; then
  echo "Health check failed: ${HEALTH_URL}" >&2
  docker compose "${compose_args[@]}" ps >&2 || true
  docker compose "${compose_args[@]}" logs --tail=100 app db >&2 || true
  exit 1
fi

echo "Published commit: $(git rev-parse --short HEAD)"

#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
DEPLOY_TARGET_SHA="${DEPLOY_TARGET_SHA:-${DEPLOY_EXPECTED_SHA:-}}"
DEPLOY_REPOSITORY_URL="${DEPLOY_REPOSITORY_URL:-}"
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
if [[ -n "${DEPLOY_REPOSITORY_URL}" ]]; then
  case "${DEPLOY_REPOSITORY_URL}" in
    https://*|http://*|ssh://*|*@*:*) ;;
    *)
      echo "Invalid deployment repository URL." >&2
      exit 1
      ;;
  esac
  echo "Fetching selected repository branch ${DEPLOY_BRANCH} ..."
  git fetch --tags "${DEPLOY_REPOSITORY_URL}" "${DEPLOY_BRANCH}"
  remote_sha="$(git rev-parse FETCH_HEAD)"
  remote_label="${DEPLOY_REPOSITORY_URL}"
else
  echo "Fetching origin/${DEPLOY_BRANCH} ..."
  git fetch --prune --tags origin "${DEPLOY_BRANCH}"
  remote_sha="$(git rev-parse "origin/${DEPLOY_BRANCH}")"
  remote_label="origin/${DEPLOY_BRANCH}"
fi

target_sha="${DEPLOY_TARGET_SHA:-${remote_sha}}"
previous_sha="$(git rev-parse HEAD)"
if [[ ! "${target_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid deployment target SHA: ${target_sha}" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "${target_sha}" "${remote_sha}"; then
  echo "Deployment target ${target_sha} is not in ${remote_label} history." >&2
  exit 1
fi
if [[ "${target_sha}" != "${remote_sha}" ]]; then
  echo "Deploying selected version ${target_sha}; ${remote_label} is ${remote_sha}."
fi

compose_args=(--env-file "${ENV_FILE}" -f "${COMPOSE_FILE}")

wait_for_health() {
  for _ in {1..30}; do
    if curl --fail --silent --show-error --max-time 10 "${HEALTH_URL}" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

rollback_deployment() {
  local failure_status="$1"
  set +e
  trap - EXIT
  echo "Deployment failed; restoring commit ${previous_sha} ..." >&2
  git clean -fd
  git checkout -B "${DEPLOY_BRANCH}" "${previous_sha}"
  git reset --hard "${previous_sha}"
  docker compose "${compose_args[@]}" config --quiet
  if ! docker compose "${compose_args[@]}" build app; then
    echo "Rollback image build failed." >&2
  fi
  docker compose "${compose_args[@]}" up -d --remove-orphans
  if ! wait_for_health; then
    echo "Rollback health check failed: ${HEALTH_URL}" >&2
    docker compose "${compose_args[@]}" ps >&2 || true
    docker compose "${compose_args[@]}" logs --tail=100 app db >&2 || true
  else
    echo "Rollback completed at commit ${previous_sha}." >&2
  fi
  exit "${failure_status}"
}

deployment_exit_handler() {
  local status="$?"
  if [[ "${status}" -ne 0 ]]; then
    rollback_deployment "${status}"
  fi
}

trap deployment_exit_handler EXIT

# This directory is a dedicated deployment checkout. Keep ignored runtime files
# such as .env and backups, but remove untracked source files from bootstrapping.
git clean -fd
git checkout -B "${DEPLOY_BRANCH}" "${target_sha}"
git reset --hard "${target_sha}"

docker compose "${compose_args[@]}" config --quiet

echo "Building the application image ..."
docker compose "${compose_args[@]}" build --pull app

echo "Starting the application stack ..."
docker compose "${compose_args[@]}" up -d --remove-orphans

echo "Checking ${HEALTH_URL} ..."
if ! wait_for_health; then
  echo "Health check failed: ${HEALTH_URL}" >&2
  docker compose "${compose_args[@]}" ps >&2 || true
  docker compose "${compose_args[@]}" logs --tail=100 app db >&2 || true
  exit 1
fi

echo "Published commit: $(git rev-parse --short HEAD)"

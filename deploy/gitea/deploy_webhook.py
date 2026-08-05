#!/usr/bin/env python3
"""Receive a signed Gitea webhook and expose manual deployment controls."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


LOG = logging.getLogger("gitea-deploy")
HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_TAG_RE = re.compile(
    r"^v(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?P<prerelease>-(?:0|[1-9]\d*|[0-9A-Za-z-]+)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]+))*)?"
    r"(?P<build>\+(?:[0-9A-Za-z-]+)(?:\.(?:[0-9A-Za-z-]+))*)?$"
)
WEBHOOK_SECRET = os.environ.get("GITEA_WEBHOOK_SECRET", "").encode("utf-8")
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/gitea").rstrip("/") or "/"
HEALTH_PATH = os.environ.get("HEALTH_PATH", "/healthz").rstrip("/") or "/"
WEBHOOK_BIND = os.environ.get("WEBHOOK_BIND", "0.0.0.0")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))
MAX_BODY_BYTES = int(os.environ.get("WEBHOOK_MAX_BODY_BYTES", "1048576"))
VERSION_LIST_LIMIT = max(5, min(50, int(os.environ.get("DEPLOY_VERSION_LIST_LIMIT", "30"))))
CONTROL_TOKEN = os.environ.get("DEPLOY_CONTROL_TOKEN", "").strip()
CONTROL_PATH = os.environ.get("DEPLOY_CONTROL_PATH", "/control/update").rstrip("/") or "/"
CONTROL_STATUS_PATH = os.environ.get("DEPLOY_CONTROL_STATUS_PATH", "/control/status").rstrip("/") or "/"
DEPLOY_REPO = os.environ.get("DEPLOY_REPO", "").strip()
DEPLOY_BRANCH = os.environ.get("DEPLOY_BRANCH", "main").strip()
APP_DIR = Path(os.environ.get("APP_DIR", "/opt/office-asset-mgmt")).resolve()
DEPLOY_SCRIPT = Path(
    os.environ.get(
        "DEPLOY_SCRIPT",
        str(APP_DIR / "deploy" / "scripts" / "update_from_gitea.sh"),
    )
).resolve()

state_lock = threading.Lock()
git_lock = threading.Lock()
deployment_running = False
deployment_pending = False
pending_sha = ""


class InvalidTargetVersionError(ValueError):
    pass


def _verify_signature(body: bytes, supplied_signature: str) -> bool:
    if not WEBHOOK_SECRET or not supplied_signature:
        return False

    signature = supplied_signature.strip()
    if signature.startswith("sha256="):
        signature = signature[7:]
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


def _enqueue_deployment(commit_sha: str) -> None:
    global deployment_pending, deployment_running, pending_sha

    with state_lock:
        pending_sha = commit_sha
        deployment_pending = True
        if deployment_running:
            return
        deployment_running = True

    threading.Thread(target=_deployment_worker, name="gitea-deploy", daemon=True).start()


def _deployment_worker() -> None:
    global deployment_pending, deployment_running, pending_sha

    while True:
        with state_lock:
            if not deployment_pending:
                deployment_running = False
                return
            deployment_pending = False
            commit_sha = pending_sha

        env = os.environ.copy()
        env["DEPLOY_BRANCH"] = DEPLOY_BRANCH
        env["DEPLOY_TARGET_SHA"] = commit_sha
        LOG.info("Starting deployment for commit %s", commit_sha)
        try:
            with git_lock:
                subprocess.run(
                    ["/bin/bash", str(DEPLOY_SCRIPT)],
                    cwd=str(APP_DIR),
                    env=env,
                    check=True,
                )
        except Exception:
            LOG.exception("Deployment failed for commit %s", commit_sha)
        else:
            LOG.info("Deployment completed for commit %s", commit_sha)


def _git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(APP_DIR), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout.strip()


def _git_sha(*args: str) -> str:
    output = _git_output(*args)
    return output.splitlines()[0].strip() if output else ""


def _fetch_remote_branch() -> None:
    subprocess.run(
        ["git", "-C", str(APP_DIR), "fetch", "--prune", "--tags", "origin", DEPLOY_BRANCH],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _current_sha() -> str:
    sha = _git_sha("rev-parse", "HEAD")
    if not HEX_SHA_RE.fullmatch(sha):
        raise RuntimeError("deployment checkout returned an invalid HEAD")
    return sha


def _latest_sha() -> str:
    sha = _git_sha("rev-parse", f"origin/{DEPLOY_BRANCH}")
    if not HEX_SHA_RE.fullmatch(sha):
        raise RuntimeError("deployment checkout returned an invalid remote branch")
    return sha


def _parse_semver_tag(tag_name: str) -> dict | None:
    match = SEMVER_TAG_RE.fullmatch(tag_name)
    if not match:
        return None

    prerelease = tuple((match.group("prerelease") or "").lstrip("-").split("."))
    if prerelease == ("",):
        prerelease = ()
    if any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in prerelease
    ):
        return None
    prerelease_key = tuple(
        (0, int(identifier)) if identifier.isdigit() else (1, identifier)
        for identifier in prerelease
    )
    return {
        "version": tag_name,
        "_sortKey": (
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
            1 if not prerelease else 0,
            prerelease_key,
        ),
    }


def _tag_commit_sha(tag_name: str) -> str:
    sha = _git_sha("rev-list", "-n", "1", f"{tag_name}^{{commit}}")
    return sha if HEX_SHA_RE.fullmatch(sha) else ""


def _commit_details(commit_sha: str) -> tuple[str, str]:
    output = _git_output("show", "-s", "--format=%aI%x1f%s", commit_sha)
    parts = output.split("\x1f", 1)
    if len(parts) != 2:
        return "", ""
    return parts[0], parts[1]


def _public_version(version: dict | None) -> dict | None:
    if not version:
        return None
    return {key: value for key, value in version.items() if not key.startswith("_")}


def _available_versions(current_sha: str) -> tuple[list[dict], dict | None, dict | None]:
    output = _git_output(
        "tag",
        "--merged",
        f"origin/{DEPLOY_BRANCH}",
        "--list",
        "v*",
    )
    versions = []
    for tag_name in output.splitlines():
        parsed = _parse_semver_tag(tag_name.strip())
        if not parsed:
            continue
        commit_sha = _tag_commit_sha(tag_name)
        if not commit_sha:
            continue
        authored_at, subject = _commit_details(commit_sha)
        versions.append(
            {
                **parsed,
                "tag": tag_name,
                "sha": commit_sha,
                "shortSha": commit_sha[:7],
                "subject": subject,
                "authoredAt": authored_at,
            }
        )

    versions.sort(key=lambda item: (item["_sortKey"], item["version"]), reverse=True)
    latest_version = versions[0] if versions else None
    current_candidates = [item for item in versions if item["sha"] == current_sha]
    if not current_candidates:
        current_candidates = [
            item for item in versions if _is_ancestor(item["sha"], current_sha)
        ]
    current_version = (
        max(current_candidates, key=lambda item: (item["_sortKey"], item["version"]))
        if current_candidates
        else None
    )
    current_sort_key = current_version["_sortKey"] if current_version else None

    for version in versions:
        version["isCurrent"] = version["sha"] == current_sha
        version["isLatest"] = version is latest_version
        version["isSelectable"] = (
            not version["isCurrent"]
            and _is_ancestor(current_sha, version["sha"])
            and (current_sort_key is None or version["_sortKey"] > current_sort_key)
        )

    display_versions = versions[:VERSION_LIST_LIMIT]
    if current_version and current_version not in display_versions:
        display_versions.append(current_version)
        display_versions.sort(key=lambda item: (item["_sortKey"], item["version"]), reverse=True)
    public_versions = [_public_version(version) for version in display_versions]
    return (
        [version for version in public_versions if version is not None],
        _public_version(current_version),
        _public_version(latest_version),
    )


def _is_ancestor(ancestor_sha: str, descendant_sha: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(APP_DIR),
            "merge-base",
            "--is-ancestor",
            ancestor_sha,
            descendant_sha,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.returncode == 0


def _is_branch_commit(commit_sha: str) -> bool:
    if not HEX_SHA_RE.fullmatch(commit_sha):
        return False
    with git_lock:
        return _is_ancestor(commit_sha, f"origin/{DEPLOY_BRANCH}")


def _snapshot_status(snapshot: dict) -> str:
    if snapshot["deploymentRunning"]:
        return "running"
    if snapshot["deploymentPending"]:
        return "queued"
    if any(version.get("isSelectable") for version in snapshot["availableVersions"]):
        return "update_available"
    if not snapshot["availableVersions"]:
        return "no_releases"
    if not snapshot.get("currentVersion"):
        return "no_release_available"
    if snapshot["currentSha"] == snapshot["latestSha"]:
        return "up_to_date"
    return "no_release_available"


def _update_snapshot() -> dict:
    with git_lock:
        _fetch_remote_branch()
        current_sha = _current_sha()
        latest_sha_remote = _latest_sha()
        versions, current_version, latest_version = _available_versions(current_sha)
    with state_lock:
        running = deployment_running
        pending = deployment_pending
    return {
        "ok": True,
        "repository": DEPLOY_REPO,
        "branch": DEPLOY_BRANCH,
        "currentSha": current_sha,
        "latestSha": latest_sha_remote,
        "currentShortSha": current_sha[:7],
        "latestShortSha": latest_sha_remote[:7],
        "currentVersion": current_version["version"] if current_version else "",
        "latestVersion": latest_version["version"] if latest_version else "",
        "currentVersionSha": current_version["sha"] if current_version else "",
        "latestVersionSha": latest_version["sha"] if latest_version else "",
        "deploymentRunning": running,
        "deploymentPending": pending,
        "availableVersions": versions,
        "automaticDeployment": False,
    }


def _check_and_queue_update(target_sha: str = "") -> dict:
    snapshot = _update_snapshot()
    target_sha = target_sha.strip().lower()
    if target_sha:
        target_version = next(
            (
                version
                for version in snapshot["availableVersions"]
                if version["sha"] == target_sha and version["isSelectable"]
            ),
            None,
        )
        if not target_version:
            raise InvalidTargetVersionError(
                "selected target is not a higher published semantic version"
            )
        snapshot["targetSha"] = target_sha
        snapshot["targetVersion"] = target_version["version"]
        _enqueue_deployment(target_sha)
        snapshot["deploymentPending"] = True
        snapshot["status"] = "queued"
        return snapshot
    snapshot["status"] = _snapshot_status(snapshot)
    return snapshot


class WebhookHandler(BaseHTTPRequestHandler):
    server_version = "GiteaDeployWebhook/1.0"

    def _reply(self, status: int, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _reply_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _control_authorized(self) -> bool:
        supplied = self.headers.get("X-Deploy-Control-Token", "")
        return bool(CONTROL_TOKEN) and hmac.compare_digest(supplied, CONTROL_TOKEN)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == HEALTH_PATH:
            self._reply(200, b"ok\n")
        elif path == CONTROL_STATUS_PATH:
            if not self._control_authorized():
                self._reply(401, b"unauthorized\n")
                return
            try:
                snapshot = _update_snapshot()
            except Exception as exc:
                LOG.exception("Unable to inspect update status")
                self._reply_json(502, {"ok": False, "error": "update_status_unavailable"})
                return
            snapshot["status"] = _snapshot_status(snapshot)
            self._reply_json(200, snapshot)
        else:
            self._reply(404, b"not found\n")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == CONTROL_PATH:
            if not self._control_authorized():
                self._reply(401, b"unauthorized\n")
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reply(400, b"invalid content length\n")
                return
            if content_length < 0 or content_length > MAX_BODY_BYTES:
                self._reply(413, b"request body too large\n")
                return
            body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._reply(400, b"invalid JSON\n")
                return
            if not isinstance(payload, dict):
                self._reply(400, b"invalid JSON object\n")
                return
            target_sha = str(payload.get("targetSha", "")).strip().lower()
            if not target_sha:
                self._reply_json(400, {"ok": False, "error": "target_version_required"})
                return
            try:
                snapshot = _check_and_queue_update(target_sha)
            except InvalidTargetVersionError:
                self._reply_json(400, {"ok": False, "error": "invalid_target_version"})
                return
            except Exception as exc:
                LOG.exception("Unable to check or queue an update")
                self._reply_json(502, {"ok": False, "error": "update_queue_unavailable"})
                return
            self._reply_json(202 if snapshot["status"] == "queued" else 200, snapshot)
            return

        if path != WEBHOOK_PATH:
            self._reply(404, b"not found\n")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, b"invalid content length\n")
            return
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self._reply(413, b"request body too large\n")
            return

        body = self.rfile.read(content_length)
        if not _verify_signature(body, self.headers.get("X-Gitea-Signature", "")):
            self._reply(401, b"invalid signature\n")
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._reply(400, b"invalid JSON\n")
            return

        event_name = self.headers.get("X-Gitea-Event", "").lower()
        repository = str(payload.get("repository", {}).get("full_name", ""))
        ref = str(payload.get("ref", ""))
        commit_sha = str(payload.get("after", "")).lower()

        if event_name != "push":
            self._reply(204)
            return
        if DEPLOY_REPO and repository != DEPLOY_REPO:
            LOG.warning("Ignoring push from unexpected repository: %s", repository)
            self._reply(204)
            return
        if ref != f"refs/heads/{DEPLOY_BRANCH}":
            self._reply(204)
            return
        if not HEX_SHA_RE.fullmatch(commit_sha) or commit_sha == "0" * 40:
            self._reply(204)
            return

        LOG.info(
            "Accepted push from %s at %s; automatic deployment is disabled, manual update is required",
            repository,
            commit_sha,
        )
        self._reply(204)

    def log_message(self, format: str, *args: object) -> None:
        LOG.info("%s - %s", self.address_string(), format % args)


def main() -> None:
    if not WEBHOOK_SECRET:
        raise SystemExit("GITEA_WEBHOOK_SECRET must be set")
    if not DEPLOY_SCRIPT.is_file():
        raise SystemExit(f"Deployment script not found: {DEPLOY_SCRIPT}")
    if not CONTROL_TOKEN:
        LOG.warning("DEPLOY_CONTROL_TOKEN is not set; manual update control is disabled")

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    server = ThreadingHTTPServer((WEBHOOK_BIND, WEBHOOK_PORT), WebhookHandler)
    LOG.info(
        "Listening on %s:%s%s (control: %s)",
        WEBHOOK_BIND,
        WEBHOOK_PORT,
        WEBHOOK_PATH,
        CONTROL_PATH,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

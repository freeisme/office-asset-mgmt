import importlib.util
import re
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load_module("office_asset_server_tests", ROOT / "server.py")
deploy_webhook = load_module(
    "office_asset_deploy_webhook_tests",
    ROOT / "deploy" / "gitea" / "deploy_webhook.py",
)


def empty_snapshot(revision: int = 1) -> dict:
    return {
        "stateRevision": revision,
        **{key: [] for key in server.STATE_ARRAY_KEYS},
    }


class StateValidationTests(TestCase):
    def test_state_snapshot_requires_all_arrays_and_positive_revision(self):
        with self.assertRaises(server.ApiError):
            server.validate_state_payload({})

        invalid_revision = empty_snapshot(0)
        with self.assertRaises(server.ApiError):
            server.validate_state_payload(invalid_revision)

        server.validate_state_payload(empty_snapshot())

    def test_generated_sync_sql_does_not_select_a_fixed_database(self):
        with mock.patch.object(server, "remap_existing_inventory_ids"):
            sql = server.build_sync_sql(empty_snapshot())

        self.assertNotIn("USE office_asset_mgmt", sql.upper())
        self.assertIn("START TRANSACTION;", sql)
        self.assertIn("INSERT INTO app_state_revision", sql)


class AuthenticationHardeningTests(TestCase):
    def test_password_length_limit_is_enforced_before_hashing(self):
        with self.assertRaises(server.ApiError):
            server.password_hash("x" * (server.PASSWORD_MAX_LENGTH + 1))

        self.assertFalse(
            server.verify_password("x" * (server.PASSWORD_MAX_LENGTH + 1), "not-a-hash")
        )

    def test_login_rate_limit_applies_to_ip_and_username(self):
        handler = SimpleNamespace(client_address=("198.51.100.10", 4321))
        original_limit = server.LOGIN_RATE_MAX_ATTEMPTS
        server.LOGIN_RATE_BUCKETS.clear()
        server.LOGIN_RATE_MAX_ATTEMPTS = 2
        try:
            server.enforce_login_rate_limit(handler, "admin1")
            server.enforce_login_rate_limit(handler, "admin1")
            with self.assertRaises(server.RateLimitError) as context:
                server.enforce_login_rate_limit(handler, "admin1")
            self.assertGreaterEqual(context.exception.retry_after, 1)
        finally:
            server.LOGIN_RATE_MAX_ATTEMPTS = original_limit
            server.LOGIN_RATE_BUCKETS.clear()

    def test_secure_cookie_clear_headers_match_secure_cookie_mode(self):
        original_secure = server.AUTH_COOKIE_SECURE
        server.AUTH_COOKIE_SECURE = True
        try:
            headers = server.clear_auth_cookie_headers()
        finally:
            server.AUTH_COOKIE_SECURE = original_secure

        self.assertEqual(2, len(headers))
        self.assertTrue(all("; Secure" in value for _, value in headers))


class ReleaseSelectionTests(TestCase):
    def test_only_annotated_releases_with_matching_notes_are_listed(self):
        current_sha = "a" * 40
        target_sha = "b" * 40
        tag_names = "\n".join(
            [
                "v1.0.0",
                "v1.1.0",
                "v1.2.0-rc.1",
                "v1.2.0",
                "v2.0.0",
            ]
        )
        annotated = {
            "v1.0.0": True,
            "v1.1.0": False,
            "v1.2.0-rc.1": True,
            "v1.2.0": True,
            "v2.0.0": True,
        }
        notes = {
            "v1.0.0": "初始版本说明",
            "v1.1.0": "轻量标签不应进入列表",
            "v1.2.0-rc.1": "预发布版本需要显式启用",
            "v1.2.0": "",
            "v2.0.0": "正式版本说明",
        }
        shas = {
            "v1.0.0": current_sha,
            "v1.1.0": "c" * 40,
            "v1.2.0-rc.1": "d" * 40,
            "v1.2.0": "e" * 40,
            "v2.0.0": target_sha,
        }

        with (
            mock.patch.object(deploy_webhook, "_git_output", return_value=tag_names),
            mock.patch.object(
                deploy_webhook,
                "_tag_is_annotated",
                side_effect=lambda tag: annotated[tag],
            ),
            mock.patch.object(
                deploy_webhook,
                "_release_notes_for_tag",
                side_effect=lambda tag: notes[tag],
            ),
            mock.patch.object(
                deploy_webhook,
                "_tag_commit_sha",
                side_effect=lambda tag: shas[tag],
            ),
            mock.patch.object(
                deploy_webhook,
                "_commit_details",
                return_value=("2026-08-06T00:00:00+08:00", "release"),
            ),
            mock.patch.object(
                deploy_webhook,
                "_is_ancestor",
                side_effect=lambda ancestor, descendant: ancestor == current_sha,
            ),
        ):
            versions, current, latest = deploy_webhook._available_versions(
                current_sha,
                "origin/main",
            )

        self.assertEqual(["v2.0.0", "v1.0.0"], [item["version"] for item in versions])
        self.assertEqual("v1.0.0", current["version"])
        self.assertEqual("v2.0.0", latest["version"])
        self.assertTrue(versions[0]["isSelectable"])
        self.assertFalse(versions[1]["isSelectable"])
        self.assertEqual("正式版本说明", versions[0]["releaseNotes"])

    def test_repository_url_validation_accepts_github_and_internal_gitea(self):
        valid_urls = [
            "https://github.com/freeisme/office-asset-mgmt.git",
            "ssh://git@192.168.253.25:2222/admin1/office-asset-management.git",
            "git@192.168.253.25:admin1/office-asset-management.git",
            "http://gitea.local/admin1/office-asset-management.git",
        ]

        for repository_url in valid_urls:
            with self.subTest(repository_url=repository_url):
                self.assertEqual(
                    repository_url,
                    server.normalize_update_repository_url(repository_url),
                )
                self.assertEqual(
                    repository_url,
                    deploy_webhook._normalize_repository_url(repository_url),
                )

    def test_repository_url_validation_rejects_credentials_and_local_paths(self):
        invalid_urls = [
            "https://token@github.com/freeisme/office-asset-mgmt.git",
            "https://user:token@github.com/freeisme/office-asset-mgmt.git",
            "file:///etc/passwd",
            "ext::sh -c whoami",
            "https://github.com/freeisme/office-asset-mgmt.git?token=secret",
            "http://github.com/freeisme/office-asset-mgmt.git",
        ]

        for repository_url in invalid_urls:
            with self.subTest(repository_url=repository_url):
                with self.assertRaises(server.ApiError):
                    server.normalize_update_repository_url(repository_url)
                with self.assertRaises(deploy_webhook.InvalidRepositoryUrlError):
                    deploy_webhook._normalize_repository_url(repository_url)


class DeploymentScriptTests(TestCase):
    def test_backup_script_uses_atomic_private_output(self):
        script = (ROOT / "deploy" / "scripts" / "backup_database.sh").read_text(
            encoding="utf-8"
        )

        for option in ("--skip-lock-tables", "--no-tablespaces", "--hex-blob"):
            self.assertIn(option, script)
        self.assertIn("temporary_file=\"$(mktemp", script)
        self.assertIn('mv -- "${temporary_file}" "${backup_file}"', script)
        self.assertNotIn('> "${backup_file}"', script)

    def test_docker_initializer_does_not_put_root_password_in_arguments(self):
        script = (ROOT / "deploy" / "docker" / "init_database.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('export MYSQL_PWD="${MYSQL_ROOT_PASSWORD}"', script)
        self.assertNotIn('"--password=${MYSQL_ROOT_PASSWORD}"', script)
        self.assertIn("22_update_repository_setting.sql", script)

    def test_compose_healthcheck_keeps_mysql_password_out_of_arguments(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        docker_doc = (ROOT / "DOCKER_DEPLOY.md").read_text(encoding="utf-8")

        self.assertIn('MYSQL_PWD=\\"$$MYSQL_PASSWORD\\" mysql', compose)
        self.assertNotIn('-p"$$MYSQL_PASSWORD"', compose)
        self.assertNotIn('-p"$MYSQL_PASSWORD"', docker_doc)

    def test_security_migration_adds_session_provenance_columns(self):
        migration = (ROOT / "database" / "21_security_hardening.sql").read_text(
            encoding="utf-8"
        )

        self.assertIn("ADD COLUMN ip_address VARCHAR(64)", migration)
        self.assertIn("ADD COLUMN user_agent VARCHAR(500)", migration)

    def test_update_repository_setting_migration_exists(self):
        migration = (ROOT / "database" / "22_update_repository_setting.sql").read_text(
            encoding="utf-8"
        )

        self.assertIn("update_repository_url", migration)
        self.assertIn("ON DUPLICATE KEY UPDATE", migration)

    def test_update_script_can_fetch_selected_repository_url(self):
        script = (ROOT / "deploy" / "scripts" / "update_from_gitea.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("DEPLOY_REPOSITORY_URL", script)
        self.assertIn('git fetch --tags "${DEPLOY_REPOSITORY_URL}" "${DEPLOY_BRANCH}"', script)

    def test_version_notes_use_semver_headings(self):
        notes = (ROOT / "VERSION_NOTES.md").read_text(encoding="utf-8")
        headings = re.findall(r"^## (v\S+)$", notes, flags=re.MULTILINE)

        self.assertTrue(headings)
        self.assertTrue(all(re.fullmatch(r"v\d+\.\d+\.\d+", item) for item in headings))


class FlowRecordUiTests(TestCase):
    def test_flow_page_is_record_table_only_with_classification_and_inline_notes(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

        self.assertIn('data-page="flowControl"', index)
        self.assertIn("<span>物资流转记录</span>", index)
        self.assertIn("function renderFlowControlRecordTable(logs)", app)
        self.assertIn("function renderFlowRecordNoteEditor(log)", app)
        self.assertIn('data-form="inventory-log-note"', app)
        self.assertIn('  return: { label: "归还回收"', app)
        self.assertIn('category: "库存入库"', app)
        self.assertIn('category: "领用发放"', app)
        self.assertIn('category: "归还回收"', app)
        self.assertNotIn('data-form="flow-control"', app)
        self.assertNotIn("clear-flow-control-filters", app)
        self.assertNotIn("登记物资调动", app)


if __name__ == "__main__":
    import unittest

    unittest.main()

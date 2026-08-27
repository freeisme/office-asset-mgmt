import importlib.util
import io
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


server = load_module("office_asset_server_tests", ROOT / "server.py")
deploy_webhook = load_module(
    "office_asset_deploy_webhook_tests",
    ROOT / "deploy" / "gitea" / "deploy_webhook.py",
)
migration_runner = load_module(
    "office_asset_migration_runner_tests",
    ROOT / "tools" / "migration_runner.py",
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
                "release",
            )

        self.assertEqual(["v2.0.0", "v1.0.0"], [item["version"] for item in versions])
        self.assertEqual("v1.0.0", current["version"])
        self.assertEqual("v2.0.0", latest["version"])
        self.assertTrue(versions[0]["isSelectable"])
        self.assertFalse(versions[1]["isSelectable"])
        self.assertEqual("正式版本说明", versions[0]["releaseNotes"])

    def test_release_channel_separates_stable_and_beta_versions(self):
        current_sha = "a" * 40
        stable_sha = "b" * 40
        beta_sha = "c" * 40
        tag_names = "\n".join(
            ["v1.2.2", "v1.2.3-alpha.1", "v1.2.3-beta.1", "v1.2.3"]
        )
        tag_shas = {
            "v1.2.2": current_sha,
            "v1.2.3-alpha.1": "d" * 40,
            "v1.2.3-beta.1": beta_sha,
            "v1.2.3": stable_sha,
        }

        with (
            mock.patch.object(deploy_webhook, "_git_output", return_value=tag_names),
            mock.patch.object(deploy_webhook, "_tag_is_annotated", return_value=True),
            mock.patch.object(deploy_webhook, "_release_notes_for_tag", return_value="版本说明"),
            mock.patch.object(
                deploy_webhook,
                "_tag_commit_sha",
                side_effect=lambda tag: tag_shas[tag],
            ),
            mock.patch.object(
                deploy_webhook,
                "_commit_details",
                return_value=("2026-08-13T00:00:00+08:00", "release"),
            ),
            mock.patch.object(
                deploy_webhook,
                "_is_ancestor",
                side_effect=lambda ancestor, descendant: ancestor == current_sha,
            ),
        ):
            release_versions, _, release_latest = deploy_webhook._available_versions(
                current_sha,
                "origin/main",
                "release",
            )
            beta_versions, _, beta_latest = deploy_webhook._available_versions(
                current_sha,
                "origin/main",
                "beta",
            )

        self.assertEqual(["v1.2.3", "v1.2.2"], [item["version"] for item in release_versions])
        self.assertEqual("v1.2.3", release_latest["version"])
        self.assertEqual(["v1.2.3-beta.1"], [item["version"] for item in beta_versions])
        self.assertEqual("v1.2.3-beta.1", beta_latest["version"])
        self.assertTrue(beta_versions[0]["isSelectable"])

    def test_invalid_release_channel_is_rejected(self):
        with self.assertRaises(server.ApiError):
            server.normalize_update_release_channel("nightly")
        with self.assertRaises(ValueError):
            deploy_webhook._normalize_release_channel("nightly")

    def test_repository_url_validation_accepts_github_and_internal_gitea(self):
        valid_urls = [
            "https://github.com/freeisme/office-asset-mgmt.git",
            "ssh://git@192.0.2.10:2222/organization/office-asset-mgmt.git",
            "git@192.0.2.10:organization/office-asset-mgmt.git",
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


class UpdateFetchTests(TestCase):
    def test_fetch_retries_transient_https_failure_and_syncs_release_tags(self):
        original_attempts = deploy_webhook.GIT_FETCH_ATTEMPTS
        original_retry_seconds = deploy_webhook.GIT_FETCH_RETRY_SECONDS
        transient_error = subprocess.CalledProcessError(
            128,
            ["git", "fetch"],
            stderr="fatal: Failure when receiving data from the peer",
        )
        try:
            deploy_webhook.GIT_FETCH_ATTEMPTS = 3
            deploy_webhook.GIT_FETCH_RETRY_SECONDS = 2
            with (
                mock.patch.object(
                    deploy_webhook.subprocess,
                    "run",
                    side_effect=[
                        transient_error,
                        subprocess.CompletedProcess(["git", "fetch"], 0),
                    ],
                ) as run,
                mock.patch.object(deploy_webhook.time, "sleep") as sleep,
            ):
                deploy_webhook._fetch_repository(
                    "https://github.com/freeisme/office-asset-mgmt.git",
                    "refs/remotes/update-candidate/main",
                )
        finally:
            deploy_webhook.GIT_FETCH_ATTEMPTS = original_attempts
            deploy_webhook.GIT_FETCH_RETRY_SECONDS = original_retry_seconds

        self.assertEqual(2, run.call_count)
        command = run.call_args_list[0].args[0]
        self.assertIn("http.version=HTTP/1.1", command)
        self.assertIn("http.lowSpeedLimit=1", command)
        self.assertIn("http.lowSpeedTime=120", command)
        self.assertIn("+refs/tags/v*:refs/tags/v*", command)
        self.assertIn(
            "+refs/heads/main:refs/remotes/update-candidate/main",
            command,
        )
        sleep.assert_called_once_with(2)

    def test_fetch_does_not_retry_non_transient_failure(self):
        original_attempts = deploy_webhook.GIT_FETCH_ATTEMPTS
        non_transient_error = subprocess.CalledProcessError(
            128,
            ["git", "fetch"],
            stderr="fatal: repository access denied",
        )
        try:
            deploy_webhook.GIT_FETCH_ATTEMPTS = 3
            with (
                mock.patch.object(
                    deploy_webhook.subprocess,
                    "run",
                    side_effect=non_transient_error,
                ) as run,
                mock.patch.object(deploy_webhook.time, "sleep") as sleep,
            ):
                with self.assertRaises(deploy_webhook.RepositoryFetchError):
                    deploy_webhook._fetch_repository(
                        "https://github.com/freeisme/office-asset-mgmt.git",
                        "refs/remotes/update-candidate/main",
                    )
        finally:
            deploy_webhook.GIT_FETCH_ATTEMPTS = original_attempts

        self.assertEqual(1, run.call_count)
        sleep.assert_not_called()

    def test_update_service_maps_repository_fetch_failure_to_readable_message(self):
        original_url = server.UPDATE_SERVICE_URL
        original_token = server.UPDATE_CONTROL_TOKEN
        try:
            server.UPDATE_SERVICE_URL = "https://update-service.example.test"
            server.UPDATE_CONTROL_TOKEN = "test-token"
            response = io.BytesIO(
                b'{"ok": false, "error": "repository_fetch_failed"}'
            )
            error = server.HTTPError(
                "https://update-service.example.test/control/status",
                503,
                "Service Unavailable",
                None,
                response,
            )
            with mock.patch.object(server, "urlopen", side_effect=error):
                with self.assertRaisesRegex(
                    server.ApiError,
                    "更新项目暂时无法通过 HTTPS 获取",
                ):
                    server.request_update_service()
        finally:
            server.UPDATE_SERVICE_URL = original_url
            server.UPDATE_CONTROL_TOKEN = original_token


class DeploymentScriptTests(TestCase):
    def test_repository_layout_has_canonical_paths_and_compatibility_entries(self):
        self.assertTrue((ROOT / "database" / "bootstrap").is_dir())
        self.assertTrue((ROOT / "database" / "migrations").is_dir())
        self.assertTrue((ROOT / "database" / "manual").is_dir())
        self.assertTrue((ROOT / "tools" / "migration_runner.py").is_file())
        self.assertTrue((ROOT / "scripts" / "windows" / "deploy.ps1").is_file())
        self.assertTrue((ROOT / "docs" / "README.md").is_file())

        runner = (ROOT / "tools" / "migration_runner.py").read_text(encoding="utf-8")
        self.assertIn('ROOT_DIR = Path(__file__).resolve().parents[1]', runner)
        self.assertIn('ROOT_DIR / "database" / "migrations"', runner)

        root_runner = (ROOT / "migration_runner.py").read_text(encoding="utf-8")
        root_deploy = (ROOT / "deploy.ps1").read_text(encoding="utf-8")
        windows_deploy = (ROOT / "scripts" / "windows" / "deploy.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("from tools.migration_runner import main", root_runner)
        self.assertIn('scripts\\windows\\deploy.ps1', root_deploy)
        self.assertIn('[Alias("DbName")][string]$Database', windows_deploy)
        self.assertNotIn('[Alias("DbName")][string]$DbName', windows_deploy)

    def test_backup_script_uses_atomic_private_output(self):
        script = (ROOT / "deploy" / "scripts" / "backup_database.sh").read_text(
            encoding="utf-8"
        )

        for option in ("--skip-lock-tables", "--no-tablespaces", "--hex-blob"):
            self.assertIn(option, script)
        self.assertIn("temporary_file=\"$(mktemp", script)
        self.assertIn('mv -- "${temporary_file}" "${backup_file}"', script)
        self.assertNotIn('> "${backup_file}"', script)

    def test_compose_backup_script_uses_deployment_user_home_and_atomic_output(self):
        script = (ROOT / "deploy" / "scripts" / "backup_compose_database.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('${HOME:-/tmp}/backups/office-asset-mgmt', script)
        self.assertIn('docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" exec -T db', script)
        self.assertIn('sql_temporary_file="$(mktemp', script)
        self.assertIn('gzip --stdout -- "${sql_temporary_file}" > "${archive_temporary_file}"', script)
        self.assertIn('sha256sum "${archive_temporary_file}" > "${checksum_temporary_file}"', script)
        self.assertIn('mv -- "${archive_temporary_file}" "${backup_file}"', script)
        self.assertIn('mv -- "${checksum_temporary_file}" "${checksum_file}"', script)

    def test_docker_initializer_does_not_put_root_password_in_arguments(self):
        script = (ROOT / "deploy" / "docker" / "init_database.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('export MYSQL_PWD="${MYSQL_ROOT_PASSWORD}"', script)
        self.assertNotIn('"--password=${MYSQL_ROOT_PASSWORD}"', script)
        self.assertIn("22_update_repository_setting.sql", script)

    def test_compose_healthcheck_keeps_mysql_password_out_of_arguments(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        docker_doc = (ROOT / "docs" / "deployment" / "docker.md").read_text(
            encoding="utf-8"
        )

        self.assertIn('MYSQL_PWD=\\"$$MYSQL_PASSWORD\\" mysql', compose)
        self.assertNotIn('-p"$$MYSQL_PASSWORD"', compose)
        self.assertNotIn('-p"$MYSQL_PASSWORD"', docker_doc)

    def test_security_migration_adds_session_provenance_columns(self):
        migration = (
            ROOT / "database" / "bootstrap" / "21_security_hardening.sql"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn("ADD COLUMN ip_address VARCHAR(64)", migration)
        self.assertIn("ADD COLUMN user_agent VARCHAR(500)", migration)

    def test_legacy_security_compatibility_migration_is_first_and_idempotent(self):
        migration_path = (
            ROOT
            / "database"
            / "migrations"
            / "20260813_001_legacy_security_compatibility.sql"
        )
        migration = migration_path.read_text(encoding="utf-8")
        discovered = migration_runner.discover_migrations()

        self.assertEqual(migration_path, discovered[0].path)
        self.assertIn("CREATE TABLE IF NOT EXISTS auth_bootstrap_guard", migration)
        self.assertIn("ADD COLUMN ip_address VARCHAR(64)", migration)
        self.assertIn("ADD COLUMN user_agent VARCHAR(500)", migration)
        self.assertIn("table_name = 'auth_session') = 1", migration)

    def test_update_repository_setting_migration_exists(self):
        migration = (
            ROOT / "database" / "bootstrap" / "22_update_repository_setting.sql"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn("update_repository_url", migration)
        self.assertIn("ON DUPLICATE KEY UPDATE", migration)

    def test_update_script_can_fetch_selected_repository_url(self):
        script = (ROOT / "deploy" / "scripts" / "update_from_gitea.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("DEPLOY_REPOSITORY_URL", script)
        self.assertIn("fetch_repository()", script)
        self.assertIn("http.version=HTTP/1.1", script)
        self.assertIn("http.lowSpeedLimit=1", script)
        self.assertIn("http.lowSpeedTime=120", script)
        self.assertIn('"+refs/tags/v*:refs/tags/v*"', script)
        self.assertIn("DEPLOY_GIT_FETCH_ATTEMPTS", script)
        self.assertIn("DEPLOY_GIT_FETCH_RETRY_SECONDS", script)
        self.assertIn('build --pull app migrate', script)
        self.assertIn('up -d --wait --no-deps db', script)
        self.assertIn('stop app || true', script)
        self.assertIn('run --rm --no-deps -T migrate', script)
        self.assertIn('up -d --no-deps --remove-orphans app', script)
        self.assertNotIn('docker compose "${compose_args[@]}" up -d --remove-orphans', script)


class MigrationBaselineTests(TestCase):
    def test_existing_database_requires_explicit_baseline_adoption(self):
        with (
            mock.patch.object(migration_runner, "table_exists", return_value=False),
            mock.patch.object(migration_runner, "has_existing_business_tables", return_value=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "schema_migration registry"):
                migration_runner.prepare_migration_registry("office_asset_mgmt")

    def test_baseline_adoption_validates_legacy_schema_before_writing_registry(self):
        with (
            mock.patch.object(migration_runner, "table_exists", return_value=False),
            mock.patch.object(migration_runner, "has_existing_business_tables", return_value=True),
            mock.patch.object(
                migration_runner,
                "missing_tables",
                return_value=["auth_session"],
            ),
            mock.patch.object(migration_runner, "ensure_registry") as ensure_registry,
            mock.patch.object(migration_runner, "mark_baseline") as mark_baseline,
        ):
            with self.assertRaisesRegex(RuntimeError, "missing required tables"):
                migration_runner.prepare_migration_registry(
                    "office_asset_mgmt",
                    migration_runner.LEGACY_BASELINE_VERSION,
                )
            ensure_registry.assert_not_called()
            mark_baseline.assert_not_called()

    def test_legacy_baseline_does_not_require_compatible_security_guard(self):
        self.assertIn("auth_session", migration_runner.LEGACY_BASELINE_REQUIRED_TABLES)
        self.assertNotIn(
            "auth_bootstrap_guard",
            migration_runner.LEGACY_BASELINE_REQUIRED_TABLES,
        )

    def test_baseline_adoption_records_only_verified_legacy_baseline(self):
        with (
            mock.patch.object(migration_runner, "table_exists", return_value=False),
            mock.patch.object(migration_runner, "has_existing_business_tables", return_value=True),
            mock.patch.object(migration_runner, "missing_tables", return_value=[]),
            mock.patch.object(migration_runner, "ensure_registry") as ensure_registry,
            mock.patch.object(migration_runner, "mark_baseline") as mark_baseline,
        ):
            migration_runner.prepare_migration_registry(
                "office_asset_mgmt",
                migration_runner.LEGACY_BASELINE_VERSION,
            )

        ensure_registry.assert_called_once_with("office_asset_mgmt")
        mark_baseline.assert_called_once_with(
            "office_asset_mgmt",
            migration_runner.LEGACY_BASELINE_VERSION,
        )

    def test_only_the_known_legacy_baseline_can_be_adopted(self):
        with self.assertRaisesRegex(RuntimeError, "Unsupported baseline"):
            migration_runner.validate_legacy_baseline(
                "office_asset_mgmt",
                "legacy-unknown",
            )

    def test_version_notes_use_semver_headings(self):
        notes = (ROOT / "VERSION_NOTES.md").read_text(encoding="utf-8")
        headings = re.findall(r"^## (v\S+)$", notes, flags=re.MULTILINE)

        self.assertTrue(headings)
        self.assertTrue(
            all(
                re.fullmatch(
                    r"v\d+\.\d+\.\d+(?:-beta\.(?:0|[1-9]\d*))?",
                    item,
                )
                for item in headings
            )
        )

    def test_update_panel_has_release_channel_and_motion_support(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("DEFAULT_UPDATE_RELEASE_CHANNEL = \"beta\"", app)
        self.assertIn('data-update-release-channel', app)
        self.assertIn("releaseChannel", app)
        self.assertIn("page-enter", app)
        self.assertIn(".update-channel-row", styles)
        self.assertIn("@keyframes page-content-enter", styles)
        self.assertIn("prefers-reduced-motion", styles)


class FrontendAccessibilityAndThemeTests(TestCase):
    def test_settings_navigation_uses_cached_state_and_only_animates_page_changes(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("let lastRenderedPage = \"\";", app)
        self.assertIn("const isPageTransition = lastRenderedPage !== state.page;", app)
        self.assertIn(
            '<div${isPageTransition ? \' class="page-enter"\' : ""}>${renderPage()}</div>',
            app,
        )
        self.assertIn('if (state.page === "settings" && !settingsState.loaded)', app)
        self.assertIn("function renderIfCurrentPage(page)", app)
        self.assertIn('const targetPage = actionElement.dataset.page || "dashboard";', app)
        self.assertIn("if (targetPage === state.page) return;", app)
        self.assertIn("function syncSettingsTabsAndContent()", app)
        self.assertIn("currentTabs.replaceWith(nextTabs);", app)
        self.assertIn("currentContent.replaceWith(nextContent);", app)
        self.assertIn("if (!syncSettingsTabsAndContent()) {", app)
        for page in ("settings", "audit", "tickets", "serviceManagement", "governance", "formDesigner"):
            self.assertIn(f'renderIfCurrentPage("{page}")', app)

    def test_async_page_loads_ignore_stale_responses(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("const latestAsyncRequests = new Map();", app)
        self.assertIn("function beginAsyncRequest(key)", app)
        self.assertIn("function isLatestAsyncRequest(key, requestId)", app)
        self.assertIn("function invalidateAsyncRequests()", app)
        for request_key in (
            "audit-logs",
            "access-control-target",
            "tickets",
            "governance",
            "service-management",
            "form-designer",
        ):
            self.assertIn(f'beginAsyncRequest("{request_key}")', app)
        self.assertNotIn(".then(render)", app)

    def test_form_controls_expose_label_associations_and_permission_names(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function createControlId(name)", app)
        self.assertIn('<label for="${controlId}">', app)
        self.assertIn('<select id="${controlId}" name="${escapeHtml(', app)
        self.assertIn('id="access-target-type" data-access-target-type', app)
        self.assertIn('id="access-target-id" data-access-target-id', app)
        self.assertIn("const permissionModuleLabels =", app)
        self.assertIn("function normalizePermissionModuleName(rawName, code)", app)
        self.assertIn("function permissionModuleLabel(module)", app)
        self.assertIn("const mapped = permissionModuleLabels[code];", app)
        self.assertIn("return normalized || code;", app)
        self.assertIn('aria-label="${escapeHtml(`${permissionModuleLabel(row.module)}', app)
        self.assertIn("function readonlyField(label, value)", app)
        labels_without_for = re.findall(
            r"<label(?![^>]*\bfor=)[^>]*>(?:(?!</label>)[\s\S])*?</label>",
            app,
        )
        self.assertTrue(labels_without_for)
        for label in labels_without_for:
            self.assertRegex(label, r"<(?:input|select|textarea)\b")

    def test_theme_preserves_existing_accents_with_targeted_contrast_repairs(self):
        styles = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("v2.0.5 targeted visual repairs", styles)
        self.assertIn("--canvas: #000000;", styles)
        self.assertIn("html[data-theme=\"dark\"] .sidebar", styles)
        self.assertIn("background: #000000 !important;", styles)
        self.assertIn("html[data-theme=\"dark\"] .device-chip {", styles)
        self.assertIn("background: #0b0b0b !important;", styles)
        self.assertIn("html[data-theme=\"dark\"] .device-chip small {", styles)
        self.assertIn("html:not([data-theme=\"dark\"]) .inventory-node-main strong,", styles)
        self.assertIn("html:not([data-theme=\"dark\"]) .inventory-node-main span,", styles)
        self.assertIn("html[data-theme=\"dark\"] .inventory-panel,", styles)
        self.assertIn("html[data-theme=\"dark\"] .inventory-node-main strong,", styles)
        self.assertIn("html[data-theme=\"dark\"] .designer-workspace,", styles)
        self.assertIn("background: #7367f0 !important;", styles)
        self.assertIn("background: #252336 !important;", styles)
        self.assertIn("html:not([data-theme=\"dark\"]) .form-field label", styles)
        self.assertIn("color: var(--ink) !important;", styles)


class FlowRecordUiTests(TestCase):
    def test_flow_page_has_filters_export_classification_and_inline_notes(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

        self.assertIn('data-page="flowControl"', index)
        self.assertIn("<span>物资流转记录</span>", index)
        self.assertIn("function renderFlowControlRecordTable(logs)", app)
        self.assertIn("function renderFlowRecordNoteEditor(log)", app)
        self.assertIn("function getFilteredFlowRecords()", app)
        self.assertIn("function exportFlowRecords()", app)
        self.assertIn('data-action="export-flow-records"', app)
        self.assertIn('data-action="clear-flow-record-filters"', app)
        self.assertIn('data-filter="flowSearch"', app)
        self.assertIn('data-filter="flowEmployee"', app)
        self.assertIn('data-filter="flowStartDate"', app)
        self.assertIn('data-filter="flowEndDate"', app)
        self.assertIn('data-form="inventory-log-note"', app)
        self.assertIn('  return: { label: "归还回收"', app)
        self.assertIn('category: "库存入库"', app)
        self.assertIn('category: "领用发放"', app)
        self.assertIn('category: "归还回收"', app)
        self.assertNotIn('data-form="flow-control"', app)
        self.assertNotIn("登记物资调动", app)

    def test_text_filters_use_drafts_until_explicitly_applied(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        active_inventory_renderer = app.split("function renderInventoryPage() {", 1)[1].split(
            "\nfunction renderFlowRecordNoteEditor",
            1,
        )[0]

        self.assertIn("const deferredTextFilterNames = new Set([", app)
        self.assertIn("function filterSearchDraftValue(filterName)", app)
        self.assertIn("function applyDeferredTextFilters(filterNames)", app)
        self.assertIn("function applyInventorySearchFilter()", app)
        self.assertIn("function applyFlowRecordFilters()", app)
        self.assertIn("function applyAuditFilters()", app)
        self.assertIn('data-action="apply-inventory-search"', app)
        self.assertIn('data-action="apply-flow-record-filters"', app)
        self.assertIn('filterSearchDraftValue("inventorySearch")', active_inventory_renderer)
        self.assertIn('data-action="apply-inventory-search"', active_inventory_renderer)
        self.assertIn('filterSearchDrafts[filterName] = filter.value;', app)
        self.assertIn('if (String(filterName).startsWith("audit")) {', app)
        self.assertIn("refreshAuditLogs({ silent: true })", app)
        self.assertNotIn("renderPreservingFilterInput", app)
        self.assertNotIn("queueAuditLogRefresh", app)


class InventoryRecoveryRegressionTests(TestCase):
    def test_recovery_selection_matches_numeric_and_string_ids(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function sameRecordId(left, right)", app)
        self.assertIn("state.employees.find((employee) => sameRecordId(employee.id, id))", app)
        recovery_source = app.split("function recoveryDeviceFromSelection", 1)[1].split(
            "\nfunction openDeviceRecoveryConfirm",
            1,
        )[0]
        self.assertGreaterEqual(recovery_source.count("sameRecordId("), 2)
        self.assertIn("const selectedId = String(id);", recovery_source)

    def test_recovery_keeps_only_unprocessed_devices_after_partial_failure(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        recovery_source = app.split("async function confirmDeviceRecovery", 1)[1].split(
            "\nfunction openLeaveRecoveryModal",
            1,
        )[0]

        self.assertIn("let remainingDevices = [...pending.devices];", recovery_source)
        self.assertIn("remainingDevices = pending.devices.slice(index + 1);", recovery_source)
        self.assertIn("devices: remainingDevices", recovery_source)
        self.assertIn("if (!remainingDevices.length)", recovery_source)
        self.assertIn("openDeviceRecoveryConfirm(pending.employeeId, pending.kind, remainingDevices)", recovery_source)

    def test_legacy_usage_return_has_compatibility_route_and_transactional_guards(self):
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        router = (ROOT / "office_asset" / "api_router.py").read_text(encoding="utf-8")
        service = (ROOT / "office_asset" / "asset_service.py").read_text(encoding="utf-8")

        self.assertIn("/api/inventory/usage/${encodeURIComponent(allocationType)}/", app)
        self.assertIn("if (matches.length) return matches.length;", app)
        self.assertIn('if path.startswith("/api/inventory/usage/")', router)
        self.assertIn("len(parts) != 7", router)
        self.assertIn("def return_usage_inventory(", service)
        self.assertIn("START TRANSACTION;", service)
        self.assertIn("ORDER BY allocation_id DESC", service)
        self.assertIn("LIMIT 1", service)
        self.assertIn("FOR UPDATE;", service)
        self.assertIn("Legacy usage reconciled during return.", service)


if __name__ == "__main__":
    import unittest

    unittest.main()

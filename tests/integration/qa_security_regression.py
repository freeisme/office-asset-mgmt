from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PYTHON = Path(r"C:\Users\K3DSZ080\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe")
MYSQL = Path(r"D:\MYSQL\bin\mysql.exe")
DB_NAME = os.environ.get("DB_NAME", "office_asset_mgmt_codex_test_20260814_b")
BASE_URL = "http://127.0.0.1:8011"
PASSWORD = os.environ.get("QA_PASSWORD", "QaVerify!2026")
PREFIX = "qa_sec_"


def password_hash(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=32768,
        r=8,
        p=1,
        dklen=64,
        maxmem=64 * 1024 * 1024,
    )
    return "scrypt$N=32768,r=8,p=1${}${}".format(
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )


def sql_run(sql: str) -> None:
    env = os.environ.copy()
    env["MYSQL_PWD"] = os.environ.get("DB_PASSWORD", "")
    result = subprocess.run(
        [
            str(MYSQL),
            "--protocol=tcp",
            "--host=127.0.0.1",
            "--port=3306",
            "--user=root",
            f"--database={DB_NAME}",
            "--default-character-set=utf8mb4",
            "--batch",
            "--raw",
            "--skip-column-names",
            "--silent",
            "-e",
            sql,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def sql_scalar(sql: str) -> str:
    rows = sql_rows(sql)
    return rows[0] if rows else ""


def sql_rows(sql: str) -> list[str]:
    env = os.environ.copy()
    env["MYSQL_PWD"] = os.environ.get("DB_PASSWORD", "")
    result = subprocess.run(
        [
            str(MYSQL),
            "--protocol=tcp",
            "--host=127.0.0.1",
            "--port=3306",
            "--user=root",
            f"--database={DB_NAME}",
            "--default-character-set=utf8mb4",
            "--batch",
            "--raw",
            "--skip-column-names",
            "--silent",
            "-e",
            sql,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return [row for row in result.stdout.strip().splitlines() if row]


def cleanup() -> None:
    sql_run(
        f"""
        SET FOREIGN_KEY_CHECKS = 0;
        CREATE TEMPORARY TABLE qa_workflow_ids
        SELECT workflow_id
        FROM service_form
        WHERE form_code LIKE '{PREFIX}%'
          AND workflow_id IS NOT NULL;
        DELETE FROM service_approval_decision
          WHERE approval_id IN (
            SELECT approval_id FROM service_approval
            WHERE requested_by IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%')
               OR (record_type = 'change' AND record_id IN (
                 SELECT change_id FROM itil_change WHERE title LIKE '[QA security]%'
               ))
          );
        DELETE FROM service_notification
          WHERE recipient_user_id IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%');
        DELETE FROM service_approval
          WHERE requested_by IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%')
             OR (record_type = 'change' AND record_id IN (
               SELECT change_id FROM itil_change WHERE title LIKE '[QA security]%'
             ));
        DELETE FROM itil_change WHERE title LIKE '[QA security]%';
        DELETE FROM itil_ticket WHERE title = '[QA security] no csrf';
        DELETE FROM service_form_field
          WHERE form_id IN (SELECT form_id FROM service_form WHERE form_code LIKE '{PREFIX}%');
        DELETE FROM service_form_permission
          WHERE form_id IN (SELECT form_id FROM service_form WHERE form_code LIKE '{PREFIX}%');
        DELETE FROM service_workflow_step
          WHERE workflow_id IN (SELECT workflow_id FROM qa_workflow_ids);
        DELETE FROM service_form WHERE form_code LIKE '{PREFIX}%';
        DELETE FROM service_workflow WHERE workflow_id IN (SELECT workflow_id FROM qa_workflow_ids);
        DROP TEMPORARY TABLE qa_workflow_ids;
        DELETE FROM auth_user_permission
          WHERE user_id IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%');
        DELETE FROM auth_role_permission
          WHERE role_id IN (SELECT role_id FROM auth_role WHERE role_code LIKE '{PREFIX}%');
        DELETE FROM auth_session
          WHERE user_id IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%');
        DELETE FROM auth_session
          WHERE user_id IN (SELECT user_id FROM user_account WHERE username = 'qa_verify_admin');
        DELETE FROM asset_status_history
          WHERE computer_id IN (
            SELECT computer_id FROM computer_asset WHERE device_name LIKE '{PREFIX}%'
          );
        DELETE FROM computer_assignment_history
          WHERE computer_id IN (
            SELECT computer_id FROM computer_asset WHERE device_name LIKE '{PREFIX}%'
          );
        DELETE FROM computer_assignment
          WHERE computer_id IN (
            SELECT computer_id FROM computer_asset WHERE device_name LIKE '{PREFIX}%'
          );
        DELETE FROM audit_log
          WHERE (entity_type = 'computer' AND entity_name LIKE '{PREFIX}%')
             OR (entity_type = 'employee' AND entity_name LIKE '{PREFIX}%')
             OR (entity_type = 'org_unit' AND entity_name LIKE '{PREFIX}%');
        DELETE FROM user_org_scope
          WHERE user_id IN (SELECT user_id FROM user_account WHERE username LIKE '{PREFIX}%');
        DELETE FROM user_account WHERE username = 'qa_verify_admin';
        DELETE FROM user_account WHERE username LIKE '{PREFIX}%';
        DELETE FROM auth_role WHERE role_code LIKE '{PREFIX}%';
        DELETE FROM computer_asset WHERE device_name LIKE '{PREFIX}%';
        DELETE FROM employee WHERE employee_no LIKE '{PREFIX}%';
        DELETE FROM org_unit WHERE org_name LIKE '{PREFIX}%';
        SET FOREIGN_KEY_CHECKS = 1;
        """
    )


class Client:
    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def csrf(self) -> str:
        return next(
            (item.value for item in self.jar if item.name == "oa_csrf"),
            "",
        )

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        expected: int | None = None,
        *,
        csrf: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if csrf and method not in {"GET", "HEAD", "OPTIONS"}:
            headers["X-CSRF-Token"] = self.csrf()
        if extra_headers:
            headers.update(extra_headers)
        request = urllib.request.Request(BASE_URL + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=12) as response:
                status = response.status
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read().decode("utf-8")
        result = json.loads(raw) if raw else {}
        if expected is not None and status != expected:
            raise AssertionError(f"{method} {path}: expected {expected}, got {status}: {result}")
        return status, result


def login(username: str) -> Client:
    last_error: object | None = None
    for _ in range(40):
        client = Client()
        status, payload = client.request(
            "POST",
            "/api/auth/login",
            {"username": username, "password": PASSWORD},
        )
        if status == 200:
            return client
        last_error = (status, payload)
        if _ == 0:
            print("QA_LOGIN_FIRST_FAILURE", status, payload, flush=True)
        time.sleep(0.4)
    raise AssertionError(f"login did not reach the QA server: {last_error}")


def main() -> int:
    cleanup()
    admin_hash = password_hash(PASSWORD)
    sql_run(
        f"""
        INSERT INTO user_account (
          username, display_name, password_hash, user_role, role_code, is_active
        )
        VALUES (
          'qa_verify_admin', 'QA Verify Admin', '{admin_hash}', 'admin', 'admin', 1
        );
        """
    )
    if os.environ.get("QA_EXTERNAL_SERVER") != "1":
        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "$listeners = Get-NetTCPConnection -LocalPort 8011 -State Listen -ErrorAction SilentlyContinue; "
                "foreach ($listener in $listeners) { Stop-Process -Id $listener.OwningProcess -Force -ErrorAction SilentlyContinue }",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        time.sleep(0.8)
    db_password = os.environ.get("DB_PASSWORD", "")
    if not db_password:
        raise RuntimeError("DB_PASSWORD environment variable is required for QA regression.")
    env = os.environ.copy()
    env.update(
        {
            "DB_PASSWORD": db_password,
            "DB_USER": "root",
            "DB_HOST": "127.0.0.1",
            "DB_PORT": "3306",
            "DB_NAME": DB_NAME,
            "MYSQL_BIN": str(MYSQL),
            "MYSQLDUMP_BIN": r"D:\MYSQL\bin\mysqldump.exe",
            "SERVER_HOST": "127.0.0.1",
            "SERVER_PORT": "8011",
        }
    )
    server = None
    in_process_server = None
    if os.environ.get("QA_INPROCESS_SERVER") == "1":
        os.environ.update(env)
        import server as app_server

        in_process_server = app_server.ThreadingHTTPServer(
            (app_server.SERVER_HOST, app_server.SERVER_PORT),
            app_server.AppHandler,
        )
        server_thread = __import__("threading").Thread(
            target=in_process_server.serve_forever,
            name="qa-http-server",
            daemon=True,
        )
        server_thread.start()
    elif os.environ.get("QA_EXTERNAL_SERVER") != "1":
        server = subprocess.Popen([str(PYTHON), "server.py"], cwd=ROOT, env=env)
    try:
        for _ in range(30):
            try:
                code, _ = Client().request("GET", "/api/health")
                if code == 200:
                    break
            except Exception:
                time.sleep(0.4)
        else:
            raise AssertionError("service did not become healthy")

        suffix = str(int(time.time()))
        role_none = f"{PREFIX}none_{suffix}"
        role_form_view = f"{PREFIX}formview_{suffix}"
        user_none = f"{PREFIX}none_user_{suffix}"
        user_form_view = f"{PREFIX}formview_user_{suffix}"
        form_code = f"{PREFIX}change_{suffix}"

        admin = login("qa_verify_admin")
        status, permissions = admin.request("GET", "/api/auth/permissions", expected=200)
        assert permissions["isSuperAdmin"] is True
        employee_ids = sql_rows(
            """
            SELECT e.employee_id
            FROM employee e
            LEFT JOIN user_account ua ON ua.employee_id = e.employee_id
            WHERE e.is_active = 1 AND ua.user_id IS NULL
            ORDER BY e.employee_id
            LIMIT 2;
            """
        )
        assert len(employee_ids) >= 2, "test database must contain two unbound active employees for account binding"

        status, _ = admin.request("PUT", "/api/state", {"stateRevision": 1})
        assert status == 405
        status, _ = admin.request(
            "POST",
            "/api/tickets",
            {"title": "[QA security] no csrf", "description": "no csrf"},
            csrf=False,
        )
        assert status == 403

        _, role = admin.request(
            "POST",
            "/api/roles",
            {
                "code": role_none,
                "name": "QA 无数据范围",
                "category": "custom",
                "isSuperAdmin": False,
                "permissions": [
                    {
                        "moduleCode": "tickets",
                        "actionCode": "view",
                        "canView": True,
                        "dataScope": "none",
                    }
                ],
            },
            201,
        )
        _, role_view = admin.request(
            "POST",
            "/api/roles",
            {
                "code": role_form_view,
                "name": "QA 表单只读",
                "category": "custom",
                "isSuperAdmin": False,
                "permissions": [
                    {
                        "moduleCode": "forms",
                        "actionCode": "view",
                        "canView": True,
                        "dataScope": "all",
                    }
                ],
            },
            201,
        )
        admin.request(
            "POST",
            "/api/users",
            {
                "username": user_none,
                "displayName": "QA 无数据用户",
                "password": PASSWORD,
                "roleCode": role_none,
                "employeeId": employee_ids[0],
            },
            201,
        )
        admin.request(
            "POST",
            "/api/users",
            {
                "username": user_form_view,
                "displayName": "QA 表单只读用户",
                "password": PASSWORD,
                "roleCode": role_form_view,
                "employeeId": employee_ids[1],
            },
            201,
        )

        restricted = login(user_none)
        assert restricted.request("GET", "/api/tickets")[0] == 403
        assert restricted.request("GET", "/api/backups")[0] == 403

        _, form_payload = admin.request(
            "POST",
            "/api/service/forms",
            {
                "code": form_code,
                "name": "QA 变更审批表单",
                "recordType": "change",
                "description": "QA security form",
                "fields": [
                    {
                        "key": "business_reason",
                        "label": "变更原因",
                        "type": "textarea",
                        "required": True,
                    }
                ],
                "workflow": {
                    "steps": [
                        {
                            "nodeType": "approval",
                            "name": "管理员审批",
                            "approverType": "role",
                            "approverRoleCode": "admin",
                            "required": True,
                        }
                    ]
                },
            },
            201,
        )
        form = form_payload["form"]
        assert form["workflowId"], form

        admin.request(
            "PUT",
            f"/api/service/forms/{form['id']}/permissions",
            {
                "permissions": [
                    {
                        "subjectType": "role",
                        "subjectId": role_view["role"]["id"],
                        "canView": False,
                        "canSubmit": False,
                        "dataScope": "none",
                    }
                ]
            },
            200,
        )
        form_reader = login(user_form_view)
        _, form_list = form_reader.request("GET", "/api/service/forms", expected=200)
        assert form_code not in {item["code"] for item in form_list["forms"]}
        assert form_reader.request("GET", f"/api/service/forms/{form['id']}/permissions")[0] == 403
        assert form_reader.request("GET", f"/api/service/forms/{form['id']}")[0] == 403

        _, change_payload = admin.request(
            "POST",
            "/api/changes",
            {
                "title": "[QA security] approval binding",
                "description": "Verify form workflow binding.",
                "type": "normal",
                "impact": "medium",
                "risk": "medium",
                "formId": form["id"],
                "customFields": {"business_reason": "test"},
            },
            201,
        )
        change = change_payload["change"]
        admin.request(
            "POST",
            f"/api/changes/{change['id']}/transitions",
            {"status": "submitted"},
            200,
        )
        _, approvals = admin.request("GET", "/api/approvals", expected=200)
        approval = next(item for item in approvals["approvals"] if item["recordId"] == change["id"])
        assert approval["workflowId"] == form["workflowId"], approval
        status, _ = admin.request(
            "POST",
            f"/api/changes/{change['id']}/transitions",
            {"status": "assessing"},
        )
        assert status == 409
        admin.request(
            "POST",
            f"/api/approvals/{approval['id']}/decision",
            {"decision": "approved", "comment": "QA approval"},
            200,
        )
        _, final_change = admin.request("GET", f"/api/changes/{change['id']}", expected=200)
        assert final_change["change"]["status"] == "approved", final_change

        asset_role_read = f"{PREFIX}assetread_{suffix}"
        asset_role_owner = f"{PREFIX}assetown_{suffix}"
        asset_role_org = f"{PREFIX}assetorg_{suffix}"
        asset_user_read = f"{PREFIX}assetread_user_{suffix}"
        asset_user_owner = f"{PREFIX}assetown_user_{suffix}"
        asset_user_org = f"{PREFIX}assetorg_user_{suffix}"
        org_a_code = f"QSA{suffix[-6:]}"
        org_b_code = f"QSB{suffix[-6:]}"

        _, org_a_payload = admin.request(
            "POST",
            "/api/resources/organization",
            {"code": org_a_code, "name": f"{PREFIX}org_a_{suffix}", "sortOrder": 9000},
            201,
        )
        _, org_b_payload = admin.request(
            "POST",
            "/api/resources/organization",
            {"code": org_b_code, "name": f"{PREFIX}org_b_{suffix}", "sortOrder": 9001},
            201,
        )
        org_a_id = org_a_payload["organization"]["id"]
        org_b_id = org_b_payload["organization"]["id"]

        def create_employee(key: str, org_id: str) -> str:
            _, employee_payload = admin.request(
                "POST",
                "/api/resources/employee",
                {
                    "employeeNo": f"{PREFIX}{key}_{suffix}",
                    "name": f"{PREFIX}{key}_{suffix}",
                    "orgId": org_id,
                    "department": "QA",
                    "status": "active",
                },
                201,
            )
            return employee_payload["employee"]["id"]

        employee_read = create_employee("asset_read", org_a_id)
        employee_owner = create_employee("asset_owner", org_a_id)
        employee_org_a = create_employee("asset_org_a", org_a_id)
        employee_org_b = create_employee("asset_org_b", org_b_id)

        def create_role(code: str, name: str, permissions: list[dict]) -> dict:
            _, payload = admin.request(
                "POST",
                "/api/roles",
                {
                    "code": code,
                    "name": name,
                    "category": "custom",
                    "isSuperAdmin": False,
                    "permissions": permissions,
                },
                201,
            )
            return payload["role"]

        create_role(
            asset_role_read,
            "QA 资产只读",
            [
                {
                    "moduleCode": "it_assets",
                    "actionCode": "view",
                    "canView": True,
                    "dataScope": "all",
                }
            ],
        )
        create_role(
            asset_role_owner,
            "QA 本人资产",
            [
                {
                    "moduleCode": "it_assets",
                    "actionCode": "view",
                    "canView": True,
                    "dataScope": "own",
                },
                {
                    "moduleCode": "inventory_operations",
                    "actionCode": "create",
                    "canCreate": True,
                    "dataScope": "own",
                },
                {
                    "moduleCode": "inventory_operations",
                    "actionCode": "update",
                    "canUpdate": True,
                    "dataScope": "own",
                },
            ],
        )
        create_role(
            asset_role_org,
            "QA 组织资产",
            [
                {
                    "moduleCode": "it_assets",
                    "actionCode": "view",
                    "canView": True,
                    "dataScope": "organization",
                },
                {
                    "moduleCode": "it_assets",
                    "actionCode": "update",
                    "canUpdate": True,
                    "dataScope": "organization",
                },
                {
                    "moduleCode": "inventory_operations",
                    "actionCode": "create",
                    "canCreate": True,
                    "dataScope": "organization",
                },
                {
                    "moduleCode": "inventory_operations",
                    "actionCode": "update",
                    "canUpdate": True,
                    "dataScope": "organization",
                },
            ],
        )

        def create_user(username: str, role_code: str, employee_id: str) -> str:
            _, user_payload = admin.request(
                "POST",
                "/api/users",
                {
                    "username": username,
                    "displayName": username,
                    "password": PASSWORD,
                    "roleCode": role_code,
                    "employeeId": employee_id,
                },
                201,
            )
            return user_payload["user"]["id"]

        user_read_id = create_user(asset_user_read, asset_role_read, employee_read)
        user_owner_id = create_user(asset_user_owner, asset_role_owner, employee_owner)
        user_org_id = create_user(asset_user_org, asset_role_org, employee_org_a)
        admin.request(
            "PUT",
            f"/api/user-org-scopes/{user_org_id}",
            {"scopes": [{"orgId": org_a_id, "includeDescendants": False}]},
            200,
        )

        def create_computer(device_name: str, org_id: str, asset_suffix: str) -> str:
            _, computer_payload = admin.request(
                "POST",
                "/api/resources/computer",
                {
                    "deviceName": device_name,
                    "orgId": org_id,
                    "deviceType": "laptop",
                    "status": "idle",
                    "fixedAssetCode": f"FA-{suffix}-{asset_suffix}",
                    "remarks": "QA regression asset",
                },
                201,
            )
            return computer_payload["computer"]["id"]

        computer_a = create_computer(f"{PREFIX}computer_a_{suffix}", org_a_id, "A")
        computer_b = create_computer(f"{PREFIX}computer_b_{suffix}", org_b_id, "B")
        status, duplicate_asset = admin.request(
            "POST",
            "/api/resources/computer",
            {
                "deviceName": f"{PREFIX}computer_duplicate_{suffix}",
                "orgId": org_a_id,
                "deviceType": "laptop",
                "status": "idle",
                "fixedAssetCode": f"FA-{suffix}-A",
            },
        )
        assert status == 409, duplicate_asset

        owner = login(asset_user_owner)
        assert owner.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            {"employeeId": employee_owner, "notes": "self assignment attempt"},
        )[0] == 403

        assignment_key = f"qaassign-{suffix}"
        assignment_payload = {"employeeId": employee_owner, "notes": "QA initial assignment"}
        _, assigned = admin.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            assignment_payload,
            201,
            extra_headers={"Idempotency-Key": assignment_key},
        )
        _, repeated_assignment = admin.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            assignment_payload,
            201,
            extra_headers={"Idempotency-Key": assignment_key},
        )
        assert assigned["assignmentId"] == repeated_assignment["assignmentId"]
        assert sql_scalar(
            f"""
            SELECT COUNT(*) FROM computer_assignment_history
            WHERE computer_id = {computer_a}
              AND employee_id = {employee_owner}
              AND assignment_status = 'active'
            """
        ) == "1"
        assert admin.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            {"employeeId": employee_org_a, "notes": "same key different payload"},
            extra_headers={"Idempotency-Key": assignment_key},
        )[0] == 409

        _, own_state = owner.request("GET", "/api/state", expected=200)
        assert [item["id"] for item in own_state["computers"]] == [computer_a], own_state["computers"]
        _, own_history = owner.request(
            "GET", f"/api/computers/{computer_a}/movement-history", expected=200
        )
        assert any(
            item["type"] == "assigned" and item["employeeId"] == employee_owner
            for item in own_history["events"]
        ), own_history
        assert owner.request(
            "GET", f"/api/computers/{computer_b}/movement-history"
        )[0] == 403

        _, returned = owner.request(
            "POST",
            f"/api/computers/{computer_a}/assignments/return",
            {"nextStatus": "idle", "notes": "QA owner return"},
            200,
        )
        assert returned["computer"]["status"] == "idle"
        assert owner.request(
            "GET", f"/api/computers/{computer_a}/movement-history"
        )[0] == 403

        admin.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            {"employeeId": employee_org_a, "notes": "QA reassignment source"},
            201,
            extra_headers={"Idempotency-Key": f"qaassign-source-{suffix}"},
        )
        admin.request(
            "POST",
            f"/api/computers/{computer_a}/assignments",
            {"employeeId": employee_org_b, "notes": "QA reassignment target"},
            201,
            extra_headers={"Idempotency-Key": f"qaassign-target-{suffix}"},
        )
        assert sql_scalar(
            f"""
            SELECT COUNT(*) FROM computer_assignment_history
            WHERE computer_id = {computer_a}
              AND employee_id = {employee_org_a}
              AND assignment_status = 'returned'
              AND returned_by IS NOT NULL
            """
        ) == "1"
        assert sql_scalar(
            f"""
            SELECT COUNT(*) FROM computer_assignment_history
            WHERE computer_id = {computer_a}
              AND employee_id = {employee_org_b}
              AND assignment_status = 'active'
              AND assigned_by IS NOT NULL
            """
        ) == "1"

        reader = login(asset_user_read)
        _, read_history = reader.request(
            "GET", f"/api/computers/{computer_a}/movement-history", expected=200
        )
        assert any(item["type"] == "returned" for item in read_history["events"]), read_history
        assert reader.request(
            "PUT",
            f"/api/resources/computer/{computer_a}",
            {"deviceName": f"{PREFIX}blocked_write_{suffix}"},
        )[0] == 403

        org_user = login(asset_user_org)
        _, org_state = org_user.request("GET", "/api/state", expected=200)
        assert computer_a in {item["id"] for item in org_state["computers"]}
        assert computer_b not in {item["id"] for item in org_state["computers"]}
        org_user.request(
            "PUT",
            f"/api/resources/computer/{computer_a}",
            {
                "deviceName": f"{PREFIX}computer_a_{suffix}",
                "orgId": org_a_id,
                "deviceType": "laptop",
                "status": "repair",
                "remarks": "QA org-scope update",
            },
            200,
        )
        assert org_user.request(
            "PUT",
            f"/api/resources/computer/{computer_b}",
            {
                "deviceName": f"{PREFIX}computer_b_{suffix}",
                "orgId": org_b_id,
                "deviceType": "laptop",
                "status": "repair",
            },
        )[0] == 403
        assert org_user.request(
            "GET", f"/api/computers/{computer_b}/movement-history"
        )[0] == 403
        _, final_history = admin.request(
            "GET", f"/api/computers/{computer_a}/movement-history", expected=200
        )
        assert any(
            item["type"] == "status_changed" and item["nextStatus"] == "repair"
            for item in final_history["events"]
        ), final_history

        print("QA_REGRESSION_PASS")
        print(
            "checks=role_creation,none_scope,csrf,state_write_retired,"
            "form_visibility,form_permission_endpoint,form_workflow_binding,"
            "approval_gate,approval_status_sync,computer_movement_history,"
            "assignment_idempotency,assignment_reassignment_audit,own_asset_scope,"
            "org_asset_scope,cross_org_denied,readonly_write_denied"
        )
        return 0
    finally:
        cleanup()
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=8)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=8)
        if in_process_server is not None:
            in_process_server.shutdown()
            in_process_server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from .scope import OrganizationScopeService
from .sql import SqlGateway, parse_bool


COMPUTER_STATUS_TRANSITIONS = {
    "in_use": {"in_use", "idle", "repair", "lost", "retired"},
    "idle": {"idle", "in_use", "repair", "lost", "retired"},
    "repair": {"repair", "idle", "in_use", "lost", "retired"},
    "lost": {"lost", "idle", "retired"},
    "retired": {"retired"},
}


@dataclass
class AssetService:
    db: SqlGateway
    scope: OrganizationScopeService
    api_error: type[Exception]
    conflict_error: type[Exception]
    forbidden_error: type[Exception]

    def _actor_id(self, context: dict) -> int:
        return self.db.integer(context.get("id"), 0)

    def _actor_name(self, context: dict) -> str:
        return self.db.text(context.get("username")) or "web"

    def _permission_scope(self, context: dict, module_code: str = "inventory_operations") -> str:
        return self.db.text((context.get("_permissionScopes") or {}).get(module_code)) or "all"

    def _actor_employee_id(self, context: dict) -> int:
        employee = context.get("employee") or {}
        return self.db.integer(employee.get("employeeId"), 0)

    def _assert_employee_scope(self, context: dict, employee_id: object) -> None:
        scope = self._permission_scope(context)
        if scope in {"own", "submitted", "assigned"}:
            actor_employee_id = self._actor_employee_id(context)
            if actor_employee_id <= 0 or actor_employee_id != self.db.integer(employee_id, 0):
                raise self.forbidden_error("This account can only access its own asset records.")

    def _assert_inventory_global_operation(self, context: dict) -> None:
        if self._permission_scope(context) not in {"all"}:
            raise self.forbidden_error("This inventory operation requires an all-data permission scope.")

    def _assert_inventory_issue_scope(self, context: dict) -> None:
        if self._permission_scope(context) not in {"all", "organization"}:
            raise self.forbidden_error(
                "Asset assignment and inventory issue require an all-data or organization data scope."
            )

    def _entity_org_id(self, entity_type: str, entity_id: int) -> int:
        queries = {
            "computer": f"SELECT COALESCE(org_unit_id, 0) FROM computer_asset WHERE computer_id = {entity_id} AND is_active = 1;",
            "employee": f"SELECT COALESCE(org_unit_id, 0) FROM employee WHERE employee_id = {entity_id} AND is_active = 1;",
            "organization": f"SELECT COALESCE(org_unit_id, 0) FROM org_unit WHERE org_unit_id = {entity_id} AND is_active = 1;",
            "ticket": f"SELECT COALESCE(org_unit_id, 0) FROM itil_ticket WHERE ticket_id = {entity_id};",
        }
        query = queries.get(entity_type)
        if not query:
            raise self.api_error("Unsupported relation entity.")
        if self.db.scalar(
            f"SELECT COUNT(*) FROM ({query[:-1]}) entity_row;"
        ) != 1:
            raise self.api_error("Relation entity does not exist.")
        return self.db.scalar(query)

    def _assert_relation_entity_access(self, entity_type: str, entity_id: int, context: dict) -> None:
        org_id = self._entity_org_id(entity_type, entity_id)
        self.scope.assert_org_access(context, org_id)
        scope = self._permission_scope(context, "organizations")
        if scope in {"all", "organization"}:
            return
        if scope == "none":
            raise self.forbidden_error("This account is not authorized to access asset relations.")

        actor_id = self._actor_id(context)
        actor_employee_id = self._actor_employee_id(context)
        if entity_type == "employee":
            if actor_employee_id > 0 and actor_employee_id == entity_id:
                return
        elif entity_type == "computer":
            assigned_employee_id = self.db.scalar(
                f"""
                SELECT COALESCE(employee_id, 0)
                FROM computer_assignment
                WHERE computer_id = {entity_id}
                  AND returned_at IS NULL
                  AND assignment_status = 'active'
                ORDER BY assignment_id DESC
                LIMIT 1;
                """
            )
            if actor_employee_id > 0 and actor_employee_id == assigned_employee_id:
                return
        elif entity_type == "organization":
            actor_org_id = self.db.integer((context.get("employee") or {}).get("orgId"), 0)
            if actor_org_id > 0 and actor_org_id == entity_id:
                return
        elif entity_type == "ticket":
            ticket = self.db.json(
                f"""
                SELECT JSON_OBJECT(
                  'createdBy', COALESCE(created_by, 0),
                  'assignedTo', COALESCE(assigned_to_user_id, 0)
                )
                FROM itil_ticket
                WHERE ticket_id = {entity_id};
                """,
                None,
            ) or {}
            if scope in {"own", "submitted"} and self.db.integer(ticket.get("createdBy"), 0) == actor_id:
                return
            if scope == "assigned" and self.db.integer(ticket.get("assignedTo"), 0) == actor_id:
                return
        raise self.forbidden_error("This account is not authorized to access this relation entity.")

    def _idempotency_result(
        self,
        operation: str,
        key: str,
        payload: dict,
    ) -> dict | None:
        if not key:
            return None
        if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
            raise self.api_error("Idempotency-Key must be 8-128 safe characters.")
        record = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'requestHash', request_hash,
              'response', response_json
            )
            FROM api_idempotency_key
            WHERE idempotency_key = {self.db.quote(key)}
              AND operation_code = {self.db.quote(operation)}
              AND expires_at > CURRENT_TIMESTAMP
            """,
            None,
        )
        if not record:
            return None
        request_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if self.db.text(record.get("requestHash")) != request_hash:
            raise self.conflict_error("The idempotency key was already used with another request.")
        return dict(record.get("response") or {})

    def _store_idempotency_result(
        self,
        operation: str,
        key: str,
        payload: dict,
        response: dict,
    ) -> None:
        if not key:
            return
        request_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.db.execute(
            f"""
            INSERT INTO api_idempotency_key (
              idempotency_key, operation_code, request_hash, response_json, expires_at
            )
            VALUES (
              {self.db.quote(key)},
              {self.db.quote(operation)},
              {self.db.quote(request_hash)},
              {self.db.json_value(response)},
              DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 24 HOUR)
            )
            ON DUPLICATE KEY UPDATE
              request_hash = VALUES(request_hash),
              response_json = VALUES(response_json),
              expires_at = VALUES(expires_at);
            """
        )

    def _computer(self, computer_id: object) -> dict:
        computer_id_int = self.db.integer(computer_id, 0)
        computer = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(asset.computer_id AS CHAR),
              'deviceName', asset.device_name,
              'orgId', COALESCE(CAST(asset.org_unit_id AS CHAR), ''),
              'deviceType', asset.device_type,
              'brand', COALESCE(asset.brand, ''),
              'model', COALESCE(asset.model, ''),
              'inventoryModelId', COALESCE(CAST(asset.inventory_model_id AS CHAR), ''),
              'cpu', COALESCE(asset.cpu, ''),
              'memory', COALESCE(asset.memory, ''),
              'storage', COALESCE(asset.storage, ''),
              'gpu', COALESCE(asset.gpu, ''),
              'fixedAssetCode', COALESCE(asset.fixed_asset_code, ''),
              'purchaseDate', COALESCE(CAST(asset.purchase_date AS CHAR), ''),
              'registeredDate', COALESCE(CAST(asset.registered_date AS CHAR), ''),
              'snSt', COALESCE(asset.sn_st, ''),
              'wifiMac', COALESCE(asset.wifi_mac, ''),
              'ethernetMac', COALESCE(asset.ethernet_mac, ''),
              'location', COALESCE(asset.location, ''),
              'department', COALESCE(asset.department, ''),
              'position', COALESCE(asset.position_name, ''),
              'status', asset.it_asset_status,
              'remarks', COALESCE(asset.remarks, ''),
              'userId', COALESCE(CAST(current_assignment.employee_id AS CHAR), '')
            )
            FROM computer_asset asset
            LEFT JOIN computer_assignment current_assignment
              ON current_assignment.computer_id = asset.computer_id
             AND current_assignment.returned_at IS NULL
             AND current_assignment.assignment_status = 'active'
            WHERE asset.computer_id = {computer_id_int}
              AND asset.is_active = 1
            """,
            None,
        )
        if not computer:
            raise self.api_error("Computer does not exist.")
        return dict(computer)

    def _employee(self, employee_id: object) -> dict:
        employee_id_int = self.db.integer(employee_id, 0)
        employee = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(employee_id AS CHAR),
              'employeeNo', employee_no,
              'name', employee_name,
              'orgId', COALESCE(CAST(org_unit_id AS CHAR), ''),
              'status', employment_status
            )
            FROM employee
            WHERE employee_id = {employee_id_int}
              AND is_active = 1
            """,
            None,
        )
        if not employee:
            raise self.api_error("Employee does not exist.")
        return dict(employee)

    def _assert_computer_record_scope(
        self,
        context: dict,
        computer: dict,
        module_code: str = "it_assets",
    ) -> None:
        scope = self._permission_scope(context, module_code)
        if scope in {"all", "organization"}:
            return
        if scope == "own":
            actor_employee_id = self._actor_employee_id(context)
            if actor_employee_id > 0 and actor_employee_id == self.db.integer(computer.get("userId"), 0):
                return
        raise self.forbidden_error("This account is not authorized to access this computer record.")

    def computer_movement_history(self, computer_id: object, context: dict) -> list[dict]:
        computer = self._computer(computer_id)
        self.scope.assert_computer_access(context, computer_id)
        self._assert_computer_record_scope(context, computer, "it_assets")
        computer_id_int = self.db.integer(computer_id, 0)
        rows = self.db.json(
            f"""
            SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
              'id', event_id,
              'type', event_type,
              'occurredAt', DATE_FORMAT(occurred_at, '%Y-%m-%d %H:%i:%s'),
              'employeeId', employee_id,
              'employeeNo', employee_no,
              'employeeName', employee_name,
              'previousStatus', previous_status,
              'nextStatus', next_status,
              'notes', notes,
              'operatedBy', operated_by
            )), JSON_ARRAY())
            FROM (
              SELECT
                CONCAT('assignment-', history.history_id, '-assigned') AS event_id,
                'assigned' AS event_type,
                history.assigned_at AS occurred_at,
                CAST(history.employee_id AS CHAR) AS employee_id,
                history.employee_no,
                history.employee_name,
                '' AS previous_status,
                'in_use' AS next_status,
                COALESCE(history.notes, '') AS notes,
                COALESCE(assigned_user.display_name, assigned_user.username, '') AS operated_by
              FROM computer_assignment_history history
              LEFT JOIN user_account assigned_user ON assigned_user.user_id = history.assigned_by
              WHERE history.computer_id = {computer_id_int}

              UNION ALL

              SELECT
                CONCAT('assignment-', history.history_id, '-returned') AS event_id,
                'returned' AS event_type,
                history.returned_at AS occurred_at,
                CAST(history.employee_id AS CHAR) AS employee_id,
                history.employee_no,
                history.employee_name,
                'in_use' AS previous_status,
                '' AS next_status,
                COALESCE(history.notes, '') AS notes,
                COALESCE(returned_user.display_name, returned_user.username, '') AS operated_by
              FROM computer_assignment_history history
              LEFT JOIN user_account returned_user ON returned_user.user_id = history.returned_by
              WHERE history.computer_id = {computer_id_int}
                AND history.returned_at IS NOT NULL

              UNION ALL

              SELECT
                CONCAT('status-', status_history.status_history_id) AS event_id,
                'status_changed' AS event_type,
                status_history.changed_at AS occurred_at,
                '' AS employee_id,
                '' AS employee_no,
                '' AS employee_name,
                status_history.previous_status,
                status_history.next_status,
                status_history.reason AS notes,
                COALESCE(status_user.display_name, status_user.username, '') AS operated_by
              FROM asset_status_history status_history
              LEFT JOIN user_account status_user ON status_user.user_id = status_history.changed_by
              WHERE status_history.computer_id = {computer_id_int}
                AND status_history.reason NOT IN ('Computer assignment', 'Computer return')
            ) movement_events
            """,
            [],
        )
        return sorted(
            list(rows or []),
            key=lambda item: (
                self.db.text(item.get("occurredAt")),
                self.db.text(item.get("id")),
            ),
            reverse=True,
        )

    def _audit_sql(
        self,
        action: str,
        entity_type: str,
        entity_id: object,
        entity_name: str,
        summary: str,
        context: dict,
        old_value: dict | None = None,
        new_value: dict | None = None,
    ) -> str:
        return f"""
        INSERT INTO audit_log (
          action_type, entity_type, entity_id, entity_name,
          old_value, new_value, summary, actor, source
        )
        VALUES (
          {self.db.quote(action)},
          {self.db.quote(entity_type)},
          {self.db.quote(str(entity_id))},
          {self.db.quote(entity_name)},
          {self.db.json_value(old_value or {})},
          {self.db.json_value(new_value or {})},
          {self.db.quote(summary[:500])},
          {self.db.quote(self._actor_name(context))},
          'api'
        )
        """

    def _conditional_audit_sql(
        self,
        action: str,
        entity_type: str,
        entity_id_sql: str,
        entity_name: str,
        summary: str,
        context: dict,
        condition: str,
        old_value: dict | None = None,
        new_value: dict | None = None,
    ) -> str:
        return f"""
        INSERT INTO audit_log (
          action_type, entity_type, entity_id, entity_name,
          old_value, new_value, summary, actor, source
        )
        SELECT
          {self.db.quote(action)},
          {self.db.quote(entity_type)},
          {entity_id_sql},
          {self.db.quote(entity_name)},
          {self.db.json_value(old_value or {})},
          {self.db.json_value(new_value or {})},
          {self.db.quote(summary[:500])},
          {self.db.quote(self._actor_name(context))},
          'api'
        FROM DUAL
        WHERE {condition}
        """

    def _normalize_status(self, value: object, default: str = "idle") -> str:
        status = self.db.text(value) or default
        if status not in COMPUTER_STATUS_TRANSITIONS:
            raise self.api_error("Unsupported computer lifecycle status.")
        return status

    def _assert_computer_unique_fields(
        self,
        computer_id: int,
        device_name: str,
        fixed_asset_code: str,
        sn_st: str,
    ) -> None:
        checks = (
            ("设备名称", "device_name", device_name),
            ("固定资产编码", "fixed_asset_code", fixed_asset_code),
            ("SN / ST", "sn_st", sn_st),
        )
        for label, column, value in checks:
            if not value:
                continue
            duplicate = self.db.scalar(
                f"""
                SELECT COUNT(*)
                FROM computer_asset
                WHERE {column} = {self.db.quote(value)}
                  AND computer_id <> {computer_id}
                """
            )
            if duplicate:
                raise self.conflict_error(f"{label} already exists.")

    def save_resource(
        self,
        resource_type: str,
        resource_id: object | None,
        payload: dict,
        context: dict,
    ) -> dict:
        if resource_type == "computer":
            return self._save_computer(resource_id, payload, context)
        if resource_type == "employee":
            return self._save_employee(resource_id, payload, context)
        if resource_type == "organization":
            return self._save_organization(resource_id, payload, context)
        if resource_type == "inventory-type":
            return self._save_inventory_type(resource_id, payload, context)
        if resource_type == "inventory-brand":
            return self._save_inventory_brand(resource_id, payload, context)
        if resource_type == "inventory-model":
            return self._save_inventory_model(resource_id, payload, context)
        raise self.api_error("Unsupported resource type.")

    def _save_computer(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        device_name = self.db.text(payload.get("deviceName"))
        if not device_name:
            raise self.api_error("Computer name is required.")
        org_id = self.db.integer(payload.get("orgId"), 0)
        self.scope.assert_org_access(context, org_id)
        status = self._normalize_status(payload.get("status"), "idle")
        values = {
            "device_name": self.db.quote(device_name),
            "org_unit_id": "NULL" if org_id <= 0 else str(org_id),
            "device_type": self.db.quote(self.db.text(payload.get("deviceType")) or "desktop"),
            "brand": self.db.quote(self.db.text(payload.get("brand"))) if self.db.text(payload.get("brand")) else "NULL",
            "model": self.db.quote(self.db.text(payload.get("model"))) if self.db.text(payload.get("model")) else "NULL",
            "inventory_model_id": (
                str(self.db.integer(payload.get("inventoryModelId"), 0))
                if self.db.integer(payload.get("inventoryModelId"), 0) > 0
                else "NULL"
            ),
            "cpu": self.db.quote(self.db.text(payload.get("cpu"))) if self.db.text(payload.get("cpu")) else "NULL",
            "memory": self.db.quote(self.db.text(payload.get("memory"))) if self.db.text(payload.get("memory")) else "NULL",
            "storage": self.db.quote(self.db.text(payload.get("storage"))) if self.db.text(payload.get("storage")) else "NULL",
            "gpu": self.db.quote(self.db.text(payload.get("gpu"))) if self.db.text(payload.get("gpu")) else "NULL",
            "fixed_asset_code": (
                self.db.quote(self.db.text(payload.get("fixedAssetCode")))
                if self.db.text(payload.get("fixedAssetCode"))
                else "NULL"
            ),
            "purchase_date": (
                self.db.quote(self.db.text(payload.get("purchaseDate")))
                if self.db.text(payload.get("purchaseDate"))
                else "NULL"
            ),
            "registered_date": (
                self.db.quote(self.db.text(payload.get("registeredDate")))
                if self.db.text(payload.get("registeredDate"))
                else "NULL"
            ),
            "sn_st": self.db.quote(self.db.text(payload.get("snSt"))) if self.db.text(payload.get("snSt")) else "NULL",
            "wifi_mac": self.db.quote(self.db.text(payload.get("wifiMac"))) if self.db.text(payload.get("wifiMac")) else "NULL",
            "ethernet_mac": (
                self.db.quote(self.db.text(payload.get("ethernetMac")))
                if self.db.text(payload.get("ethernetMac"))
                else "NULL"
            ),
            "location": self.db.quote(self.db.text(payload.get("location"))) if self.db.text(payload.get("location")) else "NULL",
            "department": (
                self.db.quote(self.db.text(payload.get("department")))
                if self.db.text(payload.get("department"))
                else "NULL"
            ),
            "position_name": (
                self.db.quote(self.db.text(payload.get("position")))
                if self.db.text(payload.get("position"))
                else "NULL"
            ),
            "it_asset_status": self.db.quote(status),
            "remarks": self.db.quote(self.db.text(payload.get("remarks"))) if self.db.text(payload.get("remarks")) else "NULL",
        }

        computer_id = self.db.integer(resource_id, 0)
        self._assert_computer_unique_fields(
            computer_id,
            device_name,
            self.db.text(payload.get("fixedAssetCode")),
            self.db.text(payload.get("snSt")),
        )
        old = self._computer(computer_id) if computer_id else None
        if old:
            self.scope.assert_org_access(context, old.get("orgId"))
            self._assert_computer_record_scope(context, old, "it_assets")
            old_status = self.db.text(old.get("status"))
            if status not in COMPUTER_STATUS_TRANSITIONS.get(old_status, set()):
                raise self.conflict_error(f"Invalid lifecycle transition: {old_status} -> {status}.")
            assignments = ",\n".join(f"{column} = {value}" for column, value in values.items())
            statements = [
                "START TRANSACTION",
                f"UPDATE computer_asset SET {assignments} WHERE computer_id = {computer_id}",
            ]
            if old_status != status:
                statements.append(
                    f"""
                    INSERT INTO asset_status_history (
                      computer_id, previous_status, next_status, reason, changed_by
                    )
                    VALUES (
                      {computer_id}, {self.db.quote(old_status)}, {self.db.quote(status)},
                      {self.db.quote(self.db.text(payload.get('statusReason')))}, {self._actor_id(context)}
                    )
                    """
                )
            statements.append(
                self._audit_sql(
                    "computer_updated",
                    "computer",
                    computer_id,
                    device_name,
                    "Computer asset updated",
                    context,
                    old,
                    {"status": status, "orgId": org_id},
                )
            )
            statements.append("COMMIT")
            self.db.execute(";\n".join(statements) + ";")
        else:
            columns = ", ".join(values.keys())
            value_sql = ", ".join(values.values())
            output = self.db.execute(
                f"""
                START TRANSACTION;
                INSERT INTO computer_asset ({columns}) VALUES ({value_sql});
                SET @new_computer_id = LAST_INSERT_ID();
                {self._audit_sql(
                    'computer_created',
                    'computer',
                    "'new'",
                    device_name,
                    'Computer asset created',
                    context,
                    None,
                    {'status': status, 'orgId': org_id},
                )};
                UPDATE audit_log
                SET entity_id = CAST(@new_computer_id AS CHAR)
                WHERE audit_log_id = LAST_INSERT_ID();
                SELECT @new_computer_id;
                COMMIT;
                """
            )
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            computer_id = self.db.integer(lines[-1] if lines else 0, 0)
            if computer_id <= 0:
                raise self.api_error("Unable to create computer.")
        return {"computer": self._computer(computer_id)}

    def _save_employee(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        employee_no = self.db.text(payload.get("employeeNo"))
        name = self.db.text(payload.get("name"))
        if not employee_no or not name:
            raise self.api_error("Employee number and name are required.")
        status = self.db.text(payload.get("status")) or "active"
        if status not in {"active", "inactive"}:
            raise self.api_error("Use the employee offboarding command for left employees.")
        org_id = self.db.integer(payload.get("orgId"), 0)
        self.scope.assert_org_access(context, org_id)
        employee_id = self.db.integer(resource_id, 0)
        old = self._employee(employee_id) if employee_id else None
        if old:
            self.scope.assert_org_access(context, old.get("orgId"))
        assignments = {
            "employee_no": self.db.quote(employee_no),
            "employee_name": self.db.quote(name),
            "org_unit_id": "NULL" if org_id <= 0 else str(org_id),
            "department": self.db.quote(self.db.text(payload.get("department"))) if self.db.text(payload.get("department")) else "NULL",
            "position_name": self.db.quote(self.db.text(payload.get("position"))) if self.db.text(payload.get("position")) else "NULL",
            "email": self.db.quote(self.db.text(payload.get("email"))) if self.db.text(payload.get("email")) else "NULL",
            "mobile": self.db.quote(self.db.text(payload.get("mobile"))) if self.db.text(payload.get("mobile")) else "NULL",
            "employment_status": self.db.quote(status),
        }
        if employee_id:
            self.db.execute(
                f"""
                START TRANSACTION;
                UPDATE employee
                SET {", ".join(f"{column} = {value}" for column, value in assignments.items())}
                WHERE employee_id = {employee_id};
                {self._audit_sql('employee_updated', 'employee', employee_id, name, 'Employee updated', context)};
                COMMIT;
                """
            )
        else:
            output = self.db.execute(
                f"""
                START TRANSACTION;
                INSERT INTO employee ({", ".join(assignments.keys())})
                VALUES ({", ".join(assignments.values())});
                SELECT LAST_INSERT_ID();
                COMMIT;
                """
            )
            employee_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        return {"employee": self._employee(employee_id)}

    def _save_organization(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        code = self.db.text(payload.get("code")).upper()
        name = self.db.text(payload.get("name"))
        if not code or not name:
            raise self.api_error("Organization code and name are required.")
        parent_id = self.db.integer(payload.get("parentId"), 0)
        self.scope.assert_org_access(context, parent_id)
        org_id = self.db.integer(resource_id, 0)
        if org_id and parent_id == org_id:
            raise self.api_error("An organization cannot be its own parent.")
        sort_order = max(0, self.db.integer(payload.get("sortOrder"), 1000))
        if org_id:
            self.scope.assert_org_access(context, org_id)
            self.db.execute(
                f"""
                START TRANSACTION;
                UPDATE org_unit
                SET org_code = {self.db.quote(code)},
                    org_name = {self.db.quote(name)},
                    parent_org_unit_id = {"NULL" if parent_id <= 0 else parent_id},
                    sort_order = {sort_order}
                WHERE org_unit_id = {org_id};
                {self._audit_sql('organization_updated', 'org_unit', org_id, name, 'Organization updated', context)};
                COMMIT;
                """
            )
        else:
            output = self.db.execute(
                f"""
                INSERT INTO org_unit (org_code, org_name, parent_org_unit_id, sort_order)
                VALUES (
                  {self.db.quote(code)},
                  {self.db.quote(name)},
                  {"NULL" if parent_id <= 0 else parent_id},
                  {sort_order}
                );
                SELECT LAST_INSERT_ID();
                """
            )
            org_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        result = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(org_unit_id AS CHAR),
              'code', org_code,
              'name', org_name,
              'parentId', COALESCE(CAST(parent_org_unit_id AS CHAR), ''),
              'sortOrder', sort_order
            )
            FROM org_unit
            WHERE org_unit_id = {org_id}
            """,
            None,
        )
        return {"organization": result}

    def _save_inventory_model(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        type_id = self.db.integer(payload.get("typeId"), 0)
        brand_id = self.db.integer(payload.get("brandId"), 0)
        name = self.db.text(payload.get("name"))
        if type_id <= 0 or brand_id <= 0 or not name:
            raise self.api_error("Inventory type, brand and model name are required.")
        model_id = self.db.integer(resource_id, 0)
        assignments = {
            "non_asset_type_id": str(type_id),
            "brand_id": str(brand_id),
            "model_name": self.db.quote(name),
            "batch_key": self.db.quote(self.db.text(payload.get("batchKey"))),
            "inbound_date": self.db.quote(self.db.text(payload.get("inboundDate"))) if self.db.text(payload.get("inboundDate")) else "NULL",
            "cpu": self.db.quote(self.db.text(payload.get("cpu"))) if self.db.text(payload.get("cpu")) else "NULL",
            "memory": self.db.quote(self.db.text(payload.get("memory"))) if self.db.text(payload.get("memory")) else "NULL",
            "storage": self.db.quote(self.db.text(payload.get("storage"))) if self.db.text(payload.get("storage")) else "NULL",
            "gpu": self.db.quote(self.db.text(payload.get("gpu"))) if self.db.text(payload.get("gpu")) else "NULL",
            "sort_order": str(max(0, self.db.integer(payload.get("sortOrder"), 1000))),
        }
        if model_id:
            self.db.execute(
                f"""
                UPDATE it_inventory_model
                SET {", ".join(f"{column} = {value}" for column, value in assignments.items())}
                WHERE model_id = {model_id} AND is_active = 1;
                """
            )
        else:
            output = self.db.execute(
                f"""
                INSERT INTO it_inventory_model ({", ".join(assignments.keys())}, quantity)
                VALUES ({", ".join(assignments.values())}, 0);
                SELECT LAST_INSERT_ID();
                """
            )
            model_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        model = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(model_id AS CHAR),
              'typeId', CAST(non_asset_type_id AS CHAR),
              'brandId', CAST(brand_id AS CHAR),
              'name', model_name,
              'quantity', quantity
            )
            FROM it_inventory_model WHERE model_id = {model_id}
            """,
            None,
        )
        return {"inventoryModel": model}

    def _save_inventory_type(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        code = self.db.text(payload.get("code")).lower()
        name = self.db.text(payload.get("name"))
        unit = self.db.text(payload.get("unit")) or "item"
        if not code or not name:
            raise self.api_error("Inventory type code and name are required.")
        type_id = self.db.integer(resource_id, 0)
        if type_id:
            self.db.execute(
                f"""
                START TRANSACTION;
                UPDATE non_asset_type
                SET type_code = {self.db.quote(code)},
                    type_name = {self.db.quote(name)},
                    unit_name = {self.db.quote(unit)}
                WHERE non_asset_type_id = {type_id} AND is_active = 1;
                {self._audit_sql(
                    'inventory_type_updated',
                    'non_asset_type',
                    type_id,
                    name,
                    'Inventory type updated',
                    context,
                )};
                COMMIT;
                """
            )
        else:
            output = self.db.execute(
                f"""
                START TRANSACTION;
                INSERT INTO non_asset_type (type_code, type_name, unit_name)
                VALUES ({self.db.quote(code)}, {self.db.quote(name)}, {self.db.quote(unit)});
                SET @new_type_id = LAST_INSERT_ID();
                {self._audit_sql(
                    'inventory_type_created',
                    'non_asset_type',
                    "'new'",
                    name,
                    'Inventory type created',
                    context,
                )};
                UPDATE audit_log
                SET entity_id = CAST(@new_type_id AS CHAR)
                WHERE audit_log_id = LAST_INSERT_ID();
                SELECT @new_type_id;
                COMMIT;
                """
            )
            type_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        inventory_type = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(non_asset_type_id AS CHAR),
              'code', type_code,
              'name', type_name,
              'unit', unit_name
            )
            FROM non_asset_type
            WHERE non_asset_type_id = {type_id} AND is_active = 1
            """,
            None,
        )
        if not inventory_type:
            raise self.api_error("Inventory type does not exist.")
        return {"inventoryType": inventory_type}

    def _save_inventory_brand(self, resource_id: object | None, payload: dict, context: dict) -> dict:
        type_id = self.db.integer(payload.get("typeId"), 0)
        name = self.db.text(payload.get("name"))
        sort_order = max(0, self.db.integer(payload.get("sortOrder"), 1000))
        if type_id <= 0 or not name:
            raise self.api_error("Inventory brand type and name are required.")
        if self.db.scalar(
            f"SELECT COUNT(*) FROM non_asset_type WHERE non_asset_type_id = {type_id} AND is_active = 1;"
        ) != 1:
            raise self.api_error("Inventory type does not exist.")
        brand_id = self.db.integer(resource_id, 0)
        if brand_id:
            self.db.execute(
                f"""
                START TRANSACTION;
                UPDATE it_inventory_brand
                SET non_asset_type_id = {type_id},
                    brand_name = {self.db.quote(name)},
                    sort_order = {sort_order}
                WHERE brand_id = {brand_id} AND is_active = 1;
                {self._audit_sql(
                    'inventory_brand_updated',
                    'it_inventory_brand',
                    brand_id,
                    name,
                    'Inventory brand updated',
                    context,
                )};
                COMMIT;
                """
            )
        else:
            output = self.db.execute(
                f"""
                START TRANSACTION;
                INSERT INTO it_inventory_brand (non_asset_type_id, brand_name, sort_order)
                VALUES ({type_id}, {self.db.quote(name)}, {sort_order});
                SET @new_brand_id = LAST_INSERT_ID();
                {self._audit_sql(
                    'inventory_brand_created',
                    'it_inventory_brand',
                    "'new'",
                    name,
                    'Inventory brand created',
                    context,
                )};
                UPDATE audit_log
                SET entity_id = CAST(@new_brand_id AS CHAR)
                WHERE audit_log_id = LAST_INSERT_ID();
                SELECT @new_brand_id;
                COMMIT;
                """
            )
            brand_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        inventory_brand = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', CAST(brand_id AS CHAR),
              'typeId', CAST(non_asset_type_id AS CHAR),
              'name', brand_name,
              'sortOrder', sort_order
            )
            FROM it_inventory_brand
            WHERE brand_id = {brand_id} AND is_active = 1
            """,
            None,
        )
        if not inventory_brand:
            raise self.api_error("Inventory brand does not exist.")
        return {"inventoryBrand": inventory_brand}

    def assign_computer(self, computer_id: object, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("computer.assign", idempotency_key, payload)
        if cached:
            return cached
        self._assert_inventory_issue_scope(context)
        computer = self._computer(computer_id)
        self.scope.assert_computer_access(context, computer_id)
        employee = self._employee(payload.get("employeeId"))
        self.scope.assert_org_access(context, employee.get("orgId"))
        self._assert_employee_scope(context, employee.get("id"))
        if self.db.text(employee.get("status")) != "active":
            raise self.conflict_error("A computer can only be assigned to an active employee.")
        if self.db.text(computer.get("status")) in {"retired", "lost"}:
            raise self.conflict_error("This computer cannot be assigned in its current lifecycle state.")
        computer_id_int = self.db.integer(computer_id, 0)
        employee_id = self.db.integer(employee.get("id"), 0)
        assigned_at = self.db.text(payload.get("assignedAt")) or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notes = self.db.text(payload.get("notes"))
        actor_id = self._actor_id(context)
        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT computer_id FROM computer_asset WHERE computer_id = {computer_id_int} FOR UPDATE;
            SELECT employee_id FROM employee WHERE employee_id = {employee_id} FOR UPDATE;
            UPDATE computer_assignment
            SET returned_at = CURRENT_TIMESTAMP, assignment_status = 'returned'
            WHERE computer_id = {computer_id_int}
              AND returned_at IS NULL
              AND assignment_status = 'active';
            UPDATE computer_assignment_history
            SET returned_at = CURRENT_TIMESTAMP,
                assignment_status = 'returned',
                returned_by = {actor_id},
                notes = CONCAT_WS(' ', notes, 'Reassigned to another employee')
            WHERE computer_id = {computer_id_int}
              AND returned_at IS NULL
              AND assignment_status = 'active';
            INSERT INTO computer_assignment (
              computer_id, employee_id, assigned_at, assignment_status, notes
            )
            VALUES (
              {computer_id_int}, {employee_id}, {self.db.quote(assigned_at)}, 'active', {self.db.quote(notes)}
            );
            SET @assignment_id = LAST_INSERT_ID();
            INSERT INTO computer_assignment_history (
              computer_id, device_name, employee_id, employee_no, employee_name,
              assigned_at, assignment_status, notes, assigned_by
            )
            SELECT
              asset.computer_id, asset.device_name, employee.employee_id, employee.employee_no,
              employee.employee_name, {self.db.quote(assigned_at)}, 'active', {self.db.quote(notes)},
              {actor_id}
            FROM computer_asset asset
            JOIN employee ON employee.employee_id = {employee_id}
            WHERE asset.computer_id = {computer_id_int};
            UPDATE computer_asset
            SET it_asset_status = 'in_use'
            WHERE computer_id = {computer_id_int};
            INSERT INTO asset_status_history (
              computer_id, previous_status, next_status, reason, changed_by
            )
            VALUES (
              {computer_id_int}, {self.db.quote(self.db.text(computer.get('status')))}, 'in_use',
              'Computer assignment', {actor_id}
            );
            {self._audit_sql(
                'computer_assigned',
                'computer',
                computer_id_int,
                self.db.text(computer.get('deviceName')),
                'Computer assigned to ' + self.db.text(employee.get('name')),
                context,
                {'userId': computer.get('userId'), 'status': computer.get('status')},
                {'userId': employee.get('id'), 'status': 'in_use'},
            )};
            SELECT @assignment_id;
            COMMIT;
            """
        )
        assignment_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        response = {"assignmentId": str(assignment_id), "computer": self._computer(computer_id_int)}
        self._store_idempotency_result("computer.assign", idempotency_key, payload, response)
        return response

    def return_computer(self, computer_id: object, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("computer.return", idempotency_key, payload)
        if cached:
            return cached
        computer = self._computer(computer_id)
        self.scope.assert_computer_access(context, computer_id)
        if self._permission_scope(context) in {"own", "submitted", "assigned"}:
            self._assert_employee_scope(context, computer.get("userId"))
        computer_id_int = self.db.integer(computer_id, 0)
        next_status = self._normalize_status(payload.get("nextStatus"), "idle")
        if next_status not in COMPUTER_STATUS_TRANSITIONS.get(self.db.text(computer.get("status")), set()):
            raise self.conflict_error("Invalid lifecycle transition for computer return.")
        notes = self.db.text(payload.get("notes"))
        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT assignment_id
            FROM computer_assignment
            WHERE computer_id = {computer_id_int}
              AND returned_at IS NULL
              AND assignment_status = 'active'
            FOR UPDATE;
            UPDATE computer_assignment
            SET returned_at = CURRENT_TIMESTAMP,
                assignment_status = 'returned',
                notes = CONCAT_WS(' ', notes, {self.db.quote(notes)})
            WHERE computer_id = {computer_id_int}
              AND returned_at IS NULL
              AND assignment_status = 'active';
            SET @returned_count = ROW_COUNT();
            INSERT INTO computer_assignment_history (
              computer_id, device_name, employee_id, employee_no, employee_name,
              assigned_at, returned_at, assignment_status, notes, returned_by
            )
            SELECT
              assignment.computer_id, asset.device_name, assignment.employee_id,
              employee.employee_no, employee.employee_name,
              assignment.assigned_at, CURRENT_TIMESTAMP, 'returned', assignment.notes,
              {self._actor_id(context)}
            FROM computer_assignment assignment
            JOIN computer_asset asset ON asset.computer_id = assignment.computer_id
            JOIN employee ON employee.employee_id = assignment.employee_id
            WHERE assignment.computer_id = {computer_id_int}
              AND assignment.returned_at IS NOT NULL
              AND @returned_count = 1
            ORDER BY assignment.assignment_id DESC
            LIMIT 1
            ON DUPLICATE KEY UPDATE
              returned_at = VALUES(returned_at),
              assignment_status = VALUES(assignment_status),
              notes = VALUES(notes),
              returned_by = VALUES(returned_by);
            UPDATE computer_asset
            SET it_asset_status = {self.db.quote(next_status)}
            WHERE computer_id = {computer_id_int}
              AND @returned_count = 1;
            INSERT INTO asset_status_history (
              computer_id, previous_status, next_status, reason, changed_by
            )
            SELECT
              {computer_id_int}, {self.db.quote(self.db.text(computer.get('status')))},
              {self.db.quote(next_status)}, 'Computer return', {self._actor_id(context)}
            FROM DUAL
            WHERE @returned_count = 1;
            SELECT @returned_count;
            COMMIT;
            """
        )
        returned_count = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        if returned_count <= 0:
            raise self.conflict_error("The computer has no active assignment to return.")
        self.db.execute(
            self._audit_sql(
                "computer_returned",
                "computer",
                computer_id_int,
                self.db.text(computer.get("deviceName")),
                "Computer returned",
                context,
                {"userId": computer.get("userId"), "status": computer.get("status")},
                {"userId": "", "status": next_status},
            )
            + ";"
        )
        response = {"computer": self._computer(computer_id_int)}
        self._store_idempotency_result("computer.return", idempotency_key, payload, response)
        return response

    def receive_inventory(self, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("inventory.receipt", idempotency_key, payload)
        if cached:
            return cached
        self._assert_inventory_global_operation(context)
        model_id = self.db.integer(payload.get("modelId"), 0)
        quantity = self.db.integer(payload.get("quantity"), 0)
        if model_id <= 0 or quantity <= 0:
            raise self.api_error("Inventory receipt requires a model and a positive quantity.")
        model = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', model.model_id,
              'typeId', model.non_asset_type_id,
              'brandId', model.brand_id,
              'modelName', model.model_name,
              'brandName', brand.brand_name,
              'typeName', type_row.type_name,
              'quantity', model.quantity
            )
            FROM it_inventory_model model
            JOIN it_inventory_brand brand ON brand.brand_id = model.brand_id
            JOIN non_asset_type type_row ON type_row.non_asset_type_id = model.non_asset_type_id
            WHERE model.model_id = {model_id} AND model.is_active = 1
            """,
            None,
        )
        if not model:
            raise self.api_error("Inventory model does not exist.")
        inbound_date = self.db.text(payload.get("inboundDate")) or datetime.now().strftime("%Y-%m-%d")
        note = self.db.text(payload.get("note"))
        source_label = self.db.text(payload.get("sourceLabel")) or "Inventory receipt"
        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT model_id FROM it_inventory_model WHERE model_id = {model_id} FOR UPDATE;
            UPDATE it_inventory_model
            SET quantity = quantity + {quantity},
                inbound_date = {self.db.quote(inbound_date)}
            WHERE model_id = {model_id};
            INSERT INTO inventory_movement_log (
              movement_direction, type_name, brand_name, model_name, quantity,
              source_label, target_label, note, trigger_action
            )
            VALUES (
              'increase', {self.db.quote(self.db.text(model.get('typeName')))},
              {self.db.quote(self.db.text(model.get('brandName')))},
              {self.db.quote(self.db.text(model.get('modelName')))}, {quantity},
              {self.db.quote(source_label)}, 'IT Inventory', {self.db.quote(note)}, 'inventory_receipt'
            );
            SET @movement_id = LAST_INSERT_ID();
            INSERT INTO inventory_purchase_log (
              type_name, brand_name, model_name, non_asset_type_id, brand_id, model_id,
              quantity, inbound_date, source_label, note, source_movement_log_id
            )
            VALUES (
              {self.db.quote(self.db.text(model.get('typeName')))},
              {self.db.quote(self.db.text(model.get('brandName')))},
              {self.db.quote(self.db.text(model.get('modelName')))},
              {self.db.integer(model.get('typeId'), 0)}, {self.db.integer(model.get('brandId'), 0)}, {model_id},
              {quantity}, {self.db.quote(inbound_date)}, {self.db.quote(source_label)},
              {self.db.quote(note)}, @movement_id
            );
            SET @purchase_id = LAST_INSERT_ID();
            {self._audit_sql(
                'inventory_received',
                'inventory_model',
                model_id,
                self.db.text(model.get('modelName')),
                'Inventory receipt',
                context,
                {'quantity': self.db.integer(model.get('quantity'), 0)},
                {'quantityDelta': quantity},
            )};
            SELECT @purchase_id;
            COMMIT;
            """
        )
        purchase_id = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        response = {"purchaseId": str(purchase_id), "modelId": str(model_id), "quantityReceived": quantity}
        self._store_idempotency_result("inventory.receipt", idempotency_key, payload, response)
        return response

    def allocate_inventory(self, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("inventory.allocate", idempotency_key, payload)
        if cached:
            return cached
        self._assert_inventory_issue_scope(context)
        allocation_type = self.db.text(payload.get("allocationType"))
        if allocation_type not in {"monitor", "non_asset"}:
            raise self.api_error("Allocation type must be monitor or non_asset.")
        employee = self._employee(payload.get("employeeId"))
        self.scope.assert_org_access(context, employee.get("orgId"))
        self._assert_employee_scope(context, employee.get("id"))
        model_id = self.db.integer(payload.get("modelId"), 0)
        quantity = self.db.integer(payload.get("quantity"), 1)
        stock_adjusted = self.db.text(payload.get("stockAdjusted")).lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        if model_id <= 0 or quantity <= 0:
            raise self.api_error("Allocation requires a model and a positive quantity.")
        if allocation_type == "monitor" and quantity != 1:
            raise self.api_error("Monitor allocation quantity must be one.")

        model = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'typeId', model.non_asset_type_id,
              'brandId', model.brand_id,
              'typeName', type_row.type_name,
              'brandName', brand.brand_name,
              'modelName', model.model_name
            )
            FROM it_inventory_model model
            JOIN it_inventory_brand brand ON brand.brand_id = model.brand_id
            JOIN non_asset_type type_row ON type_row.non_asset_type_id = model.non_asset_type_id
            WHERE model.model_id = {model_id} AND model.is_active = 1
            """,
            None,
        )
        if not model:
            raise self.api_error("Inventory model does not exist.")

        employee_id = self.db.integer(employee.get("id"), 0)
        type_id = self.db.integer(model.get("typeId"), 0)
        brand_id = self.db.integer(model.get("brandId"), 0)
        model_name = self.db.text(model.get("modelName"))
        note = self.db.text(payload.get("notes"))
        if allocation_type == "monitor":
            display_name = self.db.text(payload.get("displayName")) or self.db.text(model.get("brandName"))
            usage_sql = f"""
                INSERT INTO employee_monitor_usage (
                  employee_id, non_asset_type_id, inventory_brand_id, inventory_model_id,
                  display_name, model, quantity, stock_adjusted, notes
                )
                SELECT
                  {employee_id}, {type_id}, {brand_id}, {model_id},
                  {self.db.quote(display_name)}, {self.db.quote(model_name)}, 1,
                  {1 if stock_adjusted else 0}, {self.db.quote(note)}
                FROM DUAL
                WHERE @stock_updated = 1
                ON DUPLICATE KEY UPDATE
                  quantity = quantity + 1,
                  stock_adjusted = GREATEST(stock_adjusted, VALUES(stock_adjusted)),
                  inventory_model_id = VALUES(inventory_model_id),
                  inventory_brand_id = VALUES(inventory_brand_id);
                SELECT IF(
                  @stock_updated = 1,
                  (
                    SELECT monitor_usage_id
                    FROM employee_monitor_usage
                    WHERE employee_id = {employee_id}
                      AND display_name = {self.db.quote(display_name)}
                      AND model = {self.db.quote(model_name)}
                    LIMIT 1
                  ),
                  0
                ) INTO @usage_ref;
            """
        else:
            usage_sql = f"""
                INSERT INTO employee_non_asset_usage (
                  employee_id, non_asset_type_id, inventory_brand_id, inventory_model_id,
                  brand, model, quantity, stock_adjusted, notes
                )
                SELECT
                  {employee_id}, {type_id}, {brand_id}, {model_id},
                  {self.db.quote(self.db.text(model.get('brandName')))}, {self.db.quote(model_name)},
                  {quantity}, {1 if stock_adjusted else 0}, {self.db.quote(note)}
                FROM DUAL
                WHERE @stock_updated = 1
                ON DUPLICATE KEY UPDATE
                  quantity = quantity + VALUES(quantity),
                  stock_adjusted = GREATEST(stock_adjusted, VALUES(stock_adjusted)),
                  inventory_model_id = VALUES(inventory_model_id),
                  inventory_brand_id = VALUES(inventory_brand_id);
                SELECT IF(
                  @stock_updated = 1,
                  (
                    SELECT non_asset_usage_id
                    FROM employee_non_asset_usage
                    WHERE employee_id = {employee_id}
                      AND non_asset_type_id = {type_id}
                      AND brand = {self.db.quote(self.db.text(model.get('brandName')))}
                      AND model = {self.db.quote(model_name)}
                    LIMIT 1
                  ),
                  0
                ) INTO @usage_ref;
            """

        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT quantity INTO @available_quantity
            FROM it_inventory_model
            WHERE model_id = {model_id}
            FOR UPDATE;
            SET @stock_updated = IF(
              {1 if stock_adjusted else 0} = 0 OR @available_quantity >= {quantity},
              1,
              0
            );
            UPDATE it_inventory_model
            SET quantity = quantity - {quantity}
            WHERE model_id = {model_id}
              AND @stock_updated = 1
              AND {1 if stock_adjusted else 0} = 1;
            {usage_sql}
            INSERT INTO inventory_allocation_history (
              allocation_type, employee_id, non_asset_type_id, inventory_model_id,
              usage_record_id, quantity, stock_adjusted, status, notes, issued_by
            )
            SELECT
              {self.db.quote(allocation_type)}, {employee_id}, {type_id}, {model_id},
              @usage_ref, {quantity}, {1 if stock_adjusted else 0}, 'active',
              {self.db.quote(note)}, {self._actor_id(context)}
            FROM DUAL
            WHERE @stock_updated = 1;
            SET @allocation_id = IF(@stock_updated = 1, LAST_INSERT_ID(), 0);
            INSERT INTO inventory_movement_log (
              movement_direction, type_name, brand_name, model_name, quantity,
              source_label, target_label, note, related_employee_no, related_employee_name, trigger_action
            )
            SELECT
              'decrease', {self.db.quote(self.db.text(model.get('typeName')))},
              {self.db.quote(self.db.text(model.get('brandName')))}, {self.db.quote(model_name)}, {quantity},
              'IT Inventory', {self.db.quote(self.db.text(employee.get('name')))}, {self.db.quote(note)},
              {self.db.quote(self.db.text(employee.get('employeeNo')))},
              {self.db.quote(self.db.text(employee.get('name')))}, 'inventory_allocation'
            FROM DUAL
            WHERE @stock_updated = 1 AND {1 if stock_adjusted else 0} = 1;
            {self._conditional_audit_sql(
                'inventory_allocated',
                'inventory_allocation',
                'CAST(@allocation_id AS CHAR)',
                model_name,
                'Inventory allocated to ' + self.db.text(employee.get('name')),
                context,
                '@stock_updated = 1',
                None,
                {'quantity': quantity, 'employeeId': employee.get('id'), 'stockAdjusted': stock_adjusted},
            )};
            SELECT @stock_updated, @allocation_id, @usage_ref;
            COMMIT;
            """
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        result = (lines[-1] if lines else "").split("\t")
        stock_updated = self.db.integer(result[0] if result else 0, 0)
        allocation_id = self.db.integer(result[1] if len(result) > 1 else 0, 0)
        usage_ref = self.db.integer(result[2] if len(result) > 2 else 0, 0)
        if stock_updated != 1 or allocation_id <= 0 or usage_ref <= 0:
            raise self.conflict_error("Insufficient inventory.")
        response = {"allocationId": str(allocation_id), "usageRecordId": str(usage_ref)}
        self._store_idempotency_result("inventory.allocate", idempotency_key, payload, response)
        return response

    def adjust_inventory(self, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("inventory.adjust", idempotency_key, payload)
        if cached:
            return cached
        self._assert_inventory_global_operation(context)
        model_id = self.db.integer(payload.get("modelId"), 0)
        delta = self.db.integer(payload.get("quantityDelta"), 0)
        if model_id <= 0 or delta == 0:
            raise self.api_error("Inventory adjustment requires a model and a non-zero quantity delta.")
        model = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'typeName', type_row.type_name,
              'brandName', brand.brand_name,
              'modelName', model.model_name,
              'quantity', model.quantity
            )
            FROM it_inventory_model model
            JOIN it_inventory_brand brand ON brand.brand_id = model.brand_id
            JOIN non_asset_type type_row ON type_row.non_asset_type_id = model.non_asset_type_id
            WHERE model.model_id = {model_id} AND model.is_active = 1
            """,
            None,
        )
        if not model:
            raise self.api_error("Inventory model does not exist.")
        direction = "increase" if delta > 0 else "decrease"
        quantity = abs(delta)
        note = self.db.text(payload.get("note"))
        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT quantity INTO @current_quantity
            FROM it_inventory_model
            WHERE model_id = {model_id}
            FOR UPDATE;
            SET @adjusted = IF(@current_quantity + ({delta}) >= 0, 1, 0);
            UPDATE it_inventory_model
            SET quantity = quantity + ({delta})
            WHERE model_id = {model_id} AND @adjusted = 1;
            INSERT INTO inventory_movement_log (
              movement_direction, type_name, brand_name, model_name, quantity,
              source_label, target_label, note, trigger_action
            )
            SELECT
              {self.db.quote(direction)},
              {self.db.quote(self.db.text(model.get('typeName')))},
              {self.db.quote(self.db.text(model.get('brandName')))},
              {self.db.quote(self.db.text(model.get('modelName')))},
              {quantity},
              {self.db.quote('Manual adjustment' if delta > 0 else 'IT Inventory')},
              {self.db.quote('IT Inventory' if delta > 0 else 'Manual adjustment')},
              {self.db.quote(note)},
              'inventory_adjustment'
            FROM DUAL
            WHERE @adjusted = 1;
            {self._conditional_audit_sql(
                'inventory_adjusted',
                'inventory_model',
                self.db.quote(str(model_id)),
                self.db.text(model.get('modelName')),
                'Inventory manually adjusted',
                context,
                '@adjusted = 1',
                {'quantity': self.db.integer(model.get('quantity'), 0)},
                {'quantityDelta': delta},
            )};
            SELECT @adjusted;
            COMMIT;
            """
        )
        adjusted = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        if adjusted != 1:
            raise self.conflict_error("Inventory adjustment would make stock negative.")
        response = {"modelId": str(model_id), "quantityDelta": delta}
        self._store_idempotency_result("inventory.adjust", idempotency_key, payload, response)
        return response

    def return_inventory(self, allocation_id: object, payload: dict, context: dict, idempotency_key: str = "") -> dict:
        cached = self._idempotency_result("inventory.return", idempotency_key, payload)
        if cached:
            return cached
        allocation_id_int = self.db.integer(allocation_id, 0)
        allocation = self.db.json(
            f"""
            SELECT JSON_OBJECT(
              'id', allocation.allocation_id,
              'type', allocation.allocation_type,
              'employeeId', allocation.employee_id,
              'employeeNo', employee.employee_no,
              'employeeName', employee.employee_name,
              'orgId', COALESCE(employee.org_unit_id, 0),
              'issuedBy', COALESCE(allocation.issued_by, 0),
              'typeId', COALESCE(allocation.non_asset_type_id, 0),
              'modelId', COALESCE(allocation.inventory_model_id, 0),
              'usageRecordId', COALESCE(allocation.usage_record_id, 0),
              'quantity', allocation.quantity,
              'stockAdjusted', allocation.stock_adjusted,
              'status', allocation.status,
              'typeName', COALESCE(type_row.type_name, ''),
              'brandName', COALESCE(brand.brand_name, ''),
              'modelName', COALESCE(model.model_name, '')
            )
            FROM inventory_allocation_history allocation
            JOIN employee ON employee.employee_id = allocation.employee_id
            LEFT JOIN it_inventory_model model ON model.model_id = allocation.inventory_model_id
            LEFT JOIN it_inventory_brand brand ON brand.brand_id = model.brand_id
            LEFT JOIN non_asset_type type_row ON type_row.non_asset_type_id = allocation.non_asset_type_id
            WHERE allocation.allocation_id = {allocation_id_int}
            """,
            None,
        )
        if not allocation:
            raise self.api_error("Inventory allocation does not exist.")
        self.scope.assert_org_access(context, allocation.get("orgId"))
        scope = self._permission_scope(context)
        if scope == "own":
            self._assert_employee_scope(context, allocation.get("employeeId"))
        elif scope in {"submitted", "assigned"} and self.db.integer(
            allocation.get("issuedBy"), 0
        ) != self._actor_id(context):
            raise self.forbidden_error("This account can only return inventory it issued.")
        if self.db.text(allocation.get("status")) != "active":
            raise self.conflict_error("This inventory allocation has already been returned.")
        quantity = self.db.integer(allocation.get("quantity"), 0)
        stock_adjusted = self.db.integer(allocation.get("stockAdjusted"), 1) == 1
        usage_id = self.db.integer(allocation.get("usageRecordId"), 0)
        usage_table = "employee_monitor_usage" if self.db.text(allocation.get("type")) == "monitor" else "employee_non_asset_usage"
        usage_pk = "monitor_usage_id" if usage_table == "employee_monitor_usage" else "non_asset_usage_id"
        output = self.db.execute(
            f"""
            START TRANSACTION;
            SELECT allocation_id
            FROM inventory_allocation_history
            WHERE allocation_id = {allocation_id_int} AND status = 'active'
            FOR UPDATE;
            UPDATE inventory_allocation_history
            SET status = 'returned',
                returned_at = CURRENT_TIMESTAMP,
                returned_by = {self._actor_id(context)}
            WHERE allocation_id = {allocation_id_int}
              AND status = 'active';
            SET @returned_count = ROW_COUNT();
            UPDATE {usage_table}
            SET quantity = quantity - {quantity}
            WHERE {usage_pk} = {usage_id}
              AND quantity >= {quantity}
              AND @returned_count = 1;
            DELETE FROM {usage_table}
            WHERE {usage_pk} = {usage_id}
              AND quantity <= 0
              AND @returned_count = 1;
            UPDATE it_inventory_model
            SET quantity = quantity + {quantity}
            WHERE model_id = {self.db.integer(allocation.get('modelId'), 0)}
              AND @returned_count = 1
              AND {1 if stock_adjusted else 0} = 1;
            INSERT INTO inventory_movement_log (
              movement_direction, type_name, brand_name, model_name, quantity,
              source_label, target_label, note, related_employee_no, related_employee_name, trigger_action
            )
            SELECT
              'increase', {self.db.quote(self.db.text(allocation.get('typeName')))},
              {self.db.quote(self.db.text(allocation.get('brandName')))},
              {self.db.quote(self.db.text(allocation.get('modelName')))}, {quantity},
              {self.db.quote(self.db.text(allocation.get('employeeName')))}, 'IT Inventory',
              {self.db.quote(self.db.text(payload.get('notes')))},
              {self.db.quote(self.db.text(allocation.get('employeeNo')))},
              {self.db.quote(self.db.text(allocation.get('employeeName')))}, 'inventory_return'
            FROM DUAL
            WHERE @returned_count = 1 AND {1 if stock_adjusted else 0} = 1;
            {self._conditional_audit_sql(
                'inventory_returned',
                'inventory_allocation',
                self.db.quote(str(allocation_id_int)),
                self.db.text(allocation.get('modelName')),
                'Inventory returned',
                context,
                '@returned_count = 1',
                {'status': 'active'},
                {'status': 'returned', 'quantity': quantity, 'stockAdjusted': stock_adjusted},
            )};
            SELECT @returned_count;
            COMMIT;
            """
        )
        returned_count = self.db.integer(output.splitlines()[-1] if output else 0, 0)
        if returned_count <= 0:
            raise self.conflict_error("This inventory allocation has already been returned.")
        response = {"allocationId": str(allocation_id_int), "status": "returned"}
        self._store_idempotency_result("inventory.return", idempotency_key, payload, response)
        return response

    def list_allocations(self, context: dict, active_only: bool = True) -> list[dict]:
        where = "WHERE allocation.status = 'active'" if active_only else ""
        rows = list(
            self.db.json(
                f"""
                SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
                  'id', CAST(allocation.allocation_id AS CHAR),
                  'allocationType', allocation.allocation_type,
                  'employeeId', CAST(allocation.employee_id AS CHAR),
                  'employeeName', employee.employee_name,
                  'orgId', COALESCE(CAST(employee.org_unit_id AS CHAR), ''),
                  'issuedBy', COALESCE(CAST(allocation.issued_by AS CHAR), ''),
                  'modelId', COALESCE(CAST(allocation.inventory_model_id AS CHAR), ''),
                  'usageRecordId', COALESCE(CAST(allocation.usage_record_id AS CHAR), ''),
                  'modelName', COALESCE(model.model_name, ''),
                  'quantity', allocation.quantity,
                  'stockAdjusted', allocation.stock_adjusted,
                  'status', allocation.status,
                  'issuedAt', CAST(allocation.issued_at AS CHAR)
                )), JSON_ARRAY())
                FROM inventory_allocation_history allocation
                JOIN employee ON employee.employee_id = allocation.employee_id
                LEFT JOIN it_inventory_model model ON model.model_id = allocation.inventory_model_id
                {where}
                """,
                [],
            )
            or []
        )
        allowed = self.scope.permitted_org_ids(context)
        if allowed is not None:
            rows = [row for row in rows if self.db.integer(row.get("orgId"), 0) in allowed]
        scope = self._permission_scope(context)
        if scope == "own":
            actor_employee_id = self._actor_employee_id(context)
            return [
                row
                for row in rows
                if actor_employee_id > 0
                and self.db.integer(row.get("employeeId"), 0) == actor_employee_id
            ]
        if scope in {"submitted", "assigned"}:
            return [
                row
                for row in rows
                if self.db.integer(row.get("issuedBy"), 0) == self._actor_id(context)
            ]
        return rows

    def add_relation(self, payload: dict, context: dict) -> dict:
        source_type = self.db.text(payload.get("sourceType"))
        target_type = self.db.text(payload.get("targetType"))
        relation_type = self.db.text(payload.get("relationType"))
        source_id = self.db.integer(payload.get("sourceId"), 0)
        target_id = self.db.integer(payload.get("targetId"), 0)
        if (
            source_type not in {"computer", "employee", "organization", "ticket"}
            or target_type not in {"computer", "employee", "organization", "ticket"}
            or relation_type not in {"depends_on", "connected_to", "assigned_to", "located_at", "related_to"}
            or source_id <= 0
            or target_id <= 0
            or (source_type == target_type and source_id == target_id)
        ):
            raise self.api_error("Invalid asset relation.")
        self._assert_relation_entity_access(source_type, source_id, context)
        self._assert_relation_entity_access(target_type, target_id, context)
        self.db.execute(
            f"""
            INSERT INTO asset_relation (
              source_entity_type, source_entity_id, relation_type,
              target_entity_type, target_entity_id, notes, created_by
            )
            VALUES (
              {self.db.quote(source_type)}, {source_id}, {self.db.quote(relation_type)},
              {self.db.quote(target_type)}, {target_id}, {self.db.quote(self.db.text(payload.get('notes')))},
              {self._actor_id(context)}
            )
            ON DUPLICATE KEY UPDATE
              notes = VALUES(notes),
              is_active = 1,
              updated_at = CURRENT_TIMESTAMP;
            """
        )
        return {"ok": True}

    def list_relations(self, entity_type: str, entity_id: object, context: dict) -> list[dict]:
        entity_id_int = self.db.integer(entity_id, 0)
        if entity_type not in {"computer", "employee", "organization", "ticket"} or entity_id_int <= 0:
            raise self.api_error("Invalid relation entity.")
        self._assert_relation_entity_access(entity_type, entity_id_int, context)
        rows = list(
            self.db.json(
                f"""
                SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
                  'id', CAST(relation_id AS CHAR),
                  'sourceType', source_entity_type,
                  'sourceId', CAST(source_entity_id AS CHAR),
                  'relationType', relation_type,
                  'targetType', target_entity_type,
                  'targetId', CAST(target_entity_id AS CHAR),
                  'notes', notes
                )), JSON_ARRAY())
                FROM asset_relation
                WHERE is_active = 1
                  AND (
                    (source_entity_type = {self.db.quote(entity_type)} AND source_entity_id = {entity_id_int})
                    OR (target_entity_type = {self.db.quote(entity_type)} AND target_entity_id = {entity_id_int})
                  )
                """,
                [],
            )
            or []
        )
        visible: list[dict] = []
        for row in rows:
            try:
                self._assert_relation_entity_access(
                    self.db.text(row.get("sourceType")),
                    self.db.integer(row.get("sourceId"), 0),
                    context,
                )
                self._assert_relation_entity_access(
                    self.db.text(row.get("targetType")),
                    self.db.integer(row.get("targetId"), 0),
                    context,
                )
            except (self.forbidden_error, self.api_error):
                continue
            visible.append(row)
        return visible

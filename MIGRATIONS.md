# MySQL 迁移策略

## 基本规则

1. `database/01_schema.sql` 与同目录编号 SQL 是空库初始化材料，可能重建对象，不能用于生产库的就地升级。
2. 每个生产结构变化都必须在 `migrations/` 新增一个不可变文件，命名为 `YYYYMMDD_NNN_description.sql`。
3. `migration_runner.py` 在 `schema_migration` 中记录迁移版本、SHA-256 校验和、文件名和执行时间。
4. 已登记迁移不得修改。任何修改必须创建新的迁移文件。
5. 迁移文件不得固定 `USE database_name`。两个历史 `20260814_*` 迁移在执行时会去除旧的 `USE` 行，但校验和仍基于原文件。
6. `/api/state` 仅保留只读兼容用途；所有业务写操作使用资源接口或命令接口和独立事务。

## 迁移清单

| 文件 | 内容 |
| --- | --- |
| `20260814_001_itil_governance.sql` | ITIL 治理基础：工单、审批、SLA、变更、问题和知识库结构。 |
| `20260814_002_command_atomicity.sql` | 入库、领用、归还、分配等命令的原子性和幂等支撑。 |
| `20260817_001_access_control.sql` | 角色、模块、操作权限、用户覆盖权限和数据范围。 |
| `20260818_001_access_control_collation.sql` | 角色代码与历史账号表的排序规则兼容。 |
| `20260818_002_service_management.sql` | 服务表单、流程、通知、审批、SLA、变更、问题和知识库。 |
| `20260818_003_permission_chinese.sql` | 内置角色和权限模块名称中文化，不改变内部权限代码。 |
| `20260818_004_role_category.sql` | 管理员、普通用户、自定义角色类别。 |
| `20260819_001_form_designer_and_identity.sql` | 表单设计器与账号绑定组织人员后的自动预填。 |
| `20260819_002_access_control_hardening.sql` | 权限和数据范围边界加固。 |
| `20260819_003_form_workflow_binding.sql` | 表单与流程、审批节点绑定。 |
| `20260819_004_workflow_role_collation.sql` | 工作流角色关联的排序规则兼容。 |
| `20260820_001_computer_movement_history.sql` | 办公终端设备流转记录和详情时间线。 |

## 新数据库

```powershell
.\deploy.ps1 -User root -Database office_asset_mgmt
```

`deploy.ps1` 只在确认空库时执行历史初始化，运行 `database/21_security_hardening.sql` 和 `database/22_update_repository_setting.sql`，登记 `legacy-20260813`，再执行所有未登记的增量迁移。

Docker 的空库初始化同样登记该基线，随后 `migrate` 服务只应用 `migrations/` 中尚未登记的文件。

## 已有数据库接入

对于已有业务表但没有 `schema_migration` 的实例：

1. 创建且验证备份。
2. 确认实例已达到 `legacy-20260813` 历史结构和安全基线。
3. 显式采用基线：

```powershell
.\deploy.ps1 -User root -Database office_asset_mgmt -AdoptExistingBaseline
```

脚本不会重放历史重建 SQL。基线检查失败时应恢复备份或先补齐历史版本，而不是绕过校验。

Docker 已有数据卷缺少登记表时会使 `migrate` 失败。确认备份和基线后，执行：

```bash
docker compose run --rm --entrypoint python migrate \
  migration_runner.py --database office_asset_mgmt --mark-baseline legacy-20260813
docker compose up -d
```

## 校验

```powershell
$env:DB_PASSWORD = "<本机数据库密码>"
python .\migration_runner.py --database office_asset_mgmt --verify
```

校验失败的含义：

- `Pending migrations`：存在尚未应用的版本。
- `checksum mismatch`：已应用文件被修改，必须恢复原文件并另建迁移。
- MySQL 错误：立即停止升级，从备份和 SQL 兼容性开始排查。

## 回滚

数据库迁移不提供自动反向执行。升级前必须备份；出现不可接受的业务或结构问题时，停止应用并使用已验证的备份恢复。代码回退到旧标签不会自动撤销数据库结构。

# 办公资产与 IT 服务管理

`v2.0.0` 是面向内部 IT 资产运营与 ITIL 服务管理的单体 Web 系统。项目不包含业务数据、数据库备份、账户密码、令牌或证书。

## 模块范围

- 办公终端、IT 物资、组织架构、人员和资产关系管理。
- 入库、领用、归还、设备分配与设备归还的独立命令接口、独立事务、幂等键和审计记录。
- 办公终端详情中的设备流转时间线。
- 中文细粒度权限：角色、用户覆盖权限、模块和操作权限，以及全部/所属部门/本人等数据范围。
- 工单、服务表单设计、人员与组织信息自动预填、工作流、多级审批、SLA 计时、通知、变更管理、问题管理和知识库。
- 同步暂存、导入结果追踪和数据质量审计。
- 数据库备份、审计日志、系统设置和更新检查。

`GET /api/state` 保留为前端兼容读取接口。`PUT /api/state` 已退役并返回 `405 STATE_WRITE_RETIRED`；业务写入必须调用资源接口或命令接口。

## 技术与目录

- Python 3.10+ 标准库 HTTP 服务
- MySQL 8.0+，Docker Compose 使用 MySQL 8.4
- 原生 HTML、CSS、JavaScript，无前端构建步骤

```text
.
├── server.py                    # HTTP 路由与应用入口
├── office_asset/                # 领域服务、仓储、权限与公共逻辑
├── web/                         # 前端页面与交互
├── database/                    # 仅用于空库初始化的历史 SQL
├── migrations/                  # 可追踪、不可修改的增量迁移
├── migration_runner.py          # 迁移登记、校验和执行器
├── qa_security_regression.py    # 接口安全与权限回归测试
├── deploy/                      # Docker、原生部署、Nginx 与备份脚本
├── deploy.ps1                   # Windows 部署与升级入口
├── compose.yaml                 # MySQL、迁移器和应用编排
└── VERSION_NOTES.md             # 版本说明
```

## 新库部署

### Windows

```powershell
.\deploy.ps1 -User root -Database office_asset_mgmt
```

脚本只对空库执行 `database/` 中的历史初始化文件，随后登记 `legacy-20260813` 基线并执行 `migrations/`。数据库名只能包含字母、数字和下划线。

### Docker Compose

```bash
cp .env.example .env
# 配置 DB_PASSWORD、MYSQL_ROOT_PASSWORD；生产环境保持 AUTH_COOKIE_SECURE=true
docker compose up -d --build
```

Compose 启动顺序为 `db` 健康检查通过后执行一次 `migrate`，迁移成功后才启动 `app`。空库初始化脚本会登记 `legacy-20260813`；`migrate` 失败时应用不会启动。

## 现有数据库升级

1. 先完成并验证数据库备份。
2. 首次引入迁移登记时，确认实例已经包含 `legacy-20260813` 历史基线和安全基线。
3. 显式执行：

```powershell
.\deploy.ps1 -User root -Database office_asset_mgmt -AdoptExistingBaseline
```

4. 以后版本只执行新增的 `migrations/*.sql`。

不要对已有业务库直接运行 `database/01_schema.sql`。它含有重建对象的逻辑，仅适用于空库或明确批准的重建。

Docker 中升级已有卷且缺少登记表时，`migrate` 会停止并拒绝自动采用基线。完成备份和结构确认后，显式执行一次：

```bash
docker compose run --rm --entrypoint python migrate \
  migration_runner.py --database office_asset_mgmt --mark-baseline legacy-20260813
docker compose up -d
```

完整规则见 [MIGRATIONS.md](MIGRATIONS.md)。

## 本机隔离测试沙盒

后续测试从 GitHub 克隆后创建独立数据库，不使用生产库：

```powershell
git clone https://github.com/freeisme/office-asset-mgmt.git office-asset-mgmt-test
cd office-asset-mgmt-test
.\deploy.ps1 -User root -Database office_asset_mgmt_test

$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "3306"
$env:DB_NAME = "office_asset_mgmt_test"
$env:DB_USER = "root"
$env:DB_PASSWORD = "<仅保存在本机环境变量中的密码>"
$env:MYSQL_BIN = "D:\MYSQL\bin\mysql.exe"
$env:SERVER_HOST = "127.0.0.1"
$env:SERVER_PORT = "8011"
python .\server.py
```

访问 `http://127.0.0.1:8011/`。测试结束后停止服务并只删除测试数据库；不要删除生产数据库或将测试数据提交到 Git。

## 验证

```powershell
python -m py_compile server.py office_asset\*.py migration_runner.py qa_security_regression.py
python .\migration_runner.py --database office_asset_mgmt_test --verify
python .\qa_security_regression.py
```

前端语法检查：

```powershell
node --check web\app.js
```

## 文档

- [迁移与升级](MIGRATIONS.md)
- [版本说明](VERSION_NOTES.md)
- [GitHub 发布流程](GITHUB_RELEASE.md)
- [Docker 部署](DOCKER_DEPLOY.md)
- [Ubuntu 原生部署](DEPLOY_UBUNTU.md)
- [开发指南](DEVELOPMENT_GUIDE.md)
- [前端与接口说明](web/README.md)
- [GitHub Wiki](https://github.com/freeisme/office-asset-mgmt/wiki)

## 安全要求

- 不提交 `.env`、数据库导出、备份、日志、Excel 源数据、账号、密码、访问令牌或私钥。
- 生产环境通过 HTTPS 访问并保持 `AUTH_COOKIE_SECURE=true`。
- 权限必须由服务端校验；隐藏前端菜单不是授权控制。
- 升级前备份，迁移后执行校验和权限回归测试。

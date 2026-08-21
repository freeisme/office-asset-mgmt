# GitHub 发布流程

GitHub 仓库用于源码审查、版本标签、Release、Wiki 和自动校验。推送或创建 Release 不会自动登录服务器、执行数据库迁移或部署生产环境。

## 发布前检查

```powershell
git status --short
git diff --check
python -m compileall -q server.py office_asset tools tests migration_runner.py run_mysql_utf8.py qa_security_regression.py
node --check web\app.js
python .\tools\migration_runner.py --database office_asset_mgmt_test --verify
python .\tests\integration\qa_security_regression.py
```

确认暂存区不包含 `.env`、令牌、密码、私钥、数据库备份、测试数据库导出、日志、Excel 或 CSV 业务数据。

## v2.0.0 发布

1. 在 `VERSION_NOTES.md` 写入与标签一致的 `v2.0.0` 条目。
2. 只暂存源代码、迁移、部署脚本和文档。
3. 创建提交并推送 `main`。
4. 创建带注释标签：

```powershell
git tag -a v2.0.0 -m "Release v2.0.0"
git push github main
git push github v2.0.0
```

5. 在 GitHub Release 中选择 `v2.0.0` 标签，发布正式版本说明。
6. 更新 Wiki：架构、权限、资产操作、服务管理、迁移、测试、安全和本版本发布说明。

## 升级约束

- GitHub Release 仅表示可部署源码版本，不代表生产升级已完成。
- 生产升级前必须备份，按 [数据库迁移说明](../development/migrations.md) 执行迁移并验证。
- 只允许管理员在受控流程中选择已发布的稳定版本。
- 回退代码不会回退数据库，恢复数据必须使用已验证的备份。

## 版本命名

稳定版本使用 `vMAJOR.MINOR.PATCH`，例如 `v2.0.0`。预发布版本使用 `vMAJOR.MINOR.PATCH-beta.N`。每个标签都应对应 `VERSION_NOTES.md` 中同名版本说明。

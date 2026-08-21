# 数据库目录

- `bootstrap/`：新建空数据库时按固定顺序执行的历史初始化 SQL。文件可能包含重建对象的逻辑，禁止用于已有生产库的原地升级。
- `migrations/`：按 `YYYYMMDD_NNN_description.sql` 命名的增量迁移。已发布文件不可修改；迁移执行器会登记 SHA-256 校验和。
- `manual/`：需要人工确认后才执行的维护脚本，不被 Windows、Docker 或 Linux 初始化流程自动调用。

部署入口会先登记 `legacy-20260813` 历史基线，后续仅执行 `migrations/` 中尚未登记的文件。详细规则见 [数据库迁移说明](../docs/development/migrations.md)。

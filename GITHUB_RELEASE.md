# GitHub 代码与发布管理

GitHub 仓库仅用于代码审查、备份、版本发布和自动校验。推送到 GitHub 不会 SSH 登录
服务器、不会执行容器更新，也不会读取服务器密钥。

`.github/workflows/publish.yml` 只执行以下检查：

- Python 语法编译；
- Bash 脚本语法检查；
- 前端 JavaScript 语法检查。

请删除历史上为 GitHub Actions 自动部署而创建的以下 Secrets（如仍存在）：

- `DEPLOY_HOST`
- `DEPLOY_PORT`
- `DEPLOY_USER`
- `DEPLOY_PATH`
- `DEPLOY_BRANCH`
- `DEPLOY_PRIVATE_KEY`
- `DEPLOY_KNOWN_HOSTS`

## 推送代码

```powershell
git status
git diff --check
git add .
git diff --cached --check
git commit -m "Describe the change"
git push github main
```

## 发布版本

每个可部署版本必须先在 `VERSION_NOTES.md` 增加对应的 SemVer 条目。通过校验后创建
注释标签：

```powershell
git tag -a v1.1.0 -m "Release v1.1.0"
git push github v1.1.0
```

随后可在 GitHub 的 Releases 页面选择该标签，补充版本说明和附件。GitHub Release 不会
触发生产更新；生产环境仍由 Gitea 的管理员手动选择正式发布版本后更新。

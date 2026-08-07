# Office Asset Management

办公资产管理系统，包含：

- 办公终端台账与使用人分配
- 组织架构树和人员管理
- 显示屏、鼠标、键盘、拓展坞等 IT 物资库存
- 物资导入、库存增减和回收
- 操作日志、分类筛选与 Excel 导出
- 管理员数据库备份、每日定时计划、备份记录与密码确认下载
- 管理员手动检查 GitHub 或 Gitea 发布版本，并选择更高的语义化版本更新

本发布目录不包含任何业务数据、数据库备份、Excel 原始文件、运行日志或数据库密码。

## 技术栈

- Python 3.10+
- MySQL 8.0+
- 原生 HTML / CSS / JavaScript
- Python 标准库 HTTP 服务，无第三方 Python 依赖

## 目录

```text
.
├── database/                         # 空库初始化和结构脚本
├── deploy/
│   ├── docker/init_database.sh        # Docker 空库初始化包装脚本
│   ├── nginx/office-asset-mgmt.conf  # Nginx 反向代理示例
│   ├── systemd/                      # systemd 服务配置
│   └── scripts/                      # 初始化和备份脚本
├── web/                              # 前端页面
├── Dockerfile                        # 应用镜像构建文件
├── compose.yaml                      # 应用和 MySQL 的 Docker Compose 编排
├── .dockerignore                     # Docker 构建上下文排除规则
├── .env.example                      # 配置模板，不含真实密码
├── server.py                         # 后端服务
├── requirements.txt                  # 说明：仅使用标准库
├── DEPLOY_UBUNTU.md                  # Ubuntu 原生部署文档
├── DOCKER_DEPLOY.md                  # Docker Compose 部署文档
├── GITHUB_RELEASE.md                 # GitHub 推送与版本发布说明
└── LICENSE                           # 内部使用许可
```

## Docker Compose 启动

推荐在 Linux 服务器或 Docker Desktop 中使用 Docker Compose 运行完整的应用与 MySQL：

```bash
cp .env.example .env
# 编辑 .env，替换 DB_PASSWORD 和 MYSQL_ROOT_PASSWORD
docker compose up -d --build
```

生产环境请先通过 HTTPS 反向代理访问。仅本机调试 HTTP 时，才将 `.env` 中的
`AUTH_COOKIE_SECURE` 显式设为 `false`：

```text
http://服务器IP:8000/
```

详细的初始化、备份、升级、局域网访问和 Nginx 配置见
[DOCKER_DEPLOY.md](DOCKER_DEPLOY.md)。

## 本地启动

Linux/macOS:

```bash
cp .env.example .env
set -a
source .env
set +a
python3 server.py
```

Windows PowerShell:

```powershell
$env:DB_PASSWORD = "你的MySQL密码"
$env:MYSQL_BIN = "D:\MySQL\bin\mysql.exe"
$env:SERVER_HOST = "127.0.0.1"
$env:SERVER_PORT = "8000"
python .\server.py
```

浏览器访问：

```text
http://127.0.0.1:8000/
```

生产环境建议使用 Nginx 对外提供 HTTPS，Python 服务只监听 `127.0.0.1:8000`。

首次部署并执行 `database/19_auth_and_settings.sql` 后，首次访问会进入管理员初始化页。系统不设置固定默认密码；创建管理员后，可在“设置”页面维护账号、角色、启停状态、系统名称、登录提示语和会话时长。

## 安全要求

1. 不要把 `.env`、数据库备份、Excel 数据文件或真实密码提交到 GitHub。
2. 生产环境使用独立 MySQL 账号，不建议 Web 服务使用 `root`。
3. 对外开放时使用 HTTPS，保留 `AUTH_COOKIE_SECURE=true`，并限制服务器防火墙端口。
4. 更新控制服务使用 HTTPS 和独立控制令牌；不要将令牌或其 CA 证书私钥提交到 Git。
5. 定期执行 `deploy/scripts/backup_database.sh`，并将备份复制到独立存储。

详细部署流程见 [DEPLOY_UBUNTU.md](DEPLOY_UBUNTU.md)。

## GitHub 发布

本目录可以推送到 GitHub，但 GitHub 仅执行源码校验，不会自动登录或更新服务器。
具体推送、语义化版本标签和 Releases 流程见 [GITHUB_RELEASE.md](GITHUB_RELEASE.md)。

## 授权

本项目不是开源软件。代码仅授权给获准组织内部使用、维护和定制，禁止未经书面许可的
对外分发或商用转售。完整条款见 [LICENSE](LICENSE)。

首次发布：

```bash
cd office-asset-management-github
git init
git add .
git diff --cached --check
git commit -m "Initial release"
git branch -M main
git remote add origin <你的GitHub仓库地址>
git push -u origin main
```

不要将原始项目根目录直接提交。部署前请阅读 [DEPLOY_UBUNTU.md](DEPLOY_UBUNTU.md)。

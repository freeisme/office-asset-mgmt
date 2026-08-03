# GitHub 自动发布配置

本项目的发布流程如下：

```text
本地修改 -> push main -> GitHub Actions 检查 -> SSH 登录 Ubuntu
         -> git fetch/reset -> 重启 systemd -> /api/health 检查
```

GitHub 只保存代码。生产服务器上的 `.env`、数据库和备份不会提交到仓库。

## 1. 首次绑定 GitHub 仓库

在 GitHub 创建一个仓库，建议使用 Private 仓库。然后在 PowerShell 中执行：

```powershell
cd D:\数据库\office-asset-management-github
git init
git branch -M main
git add .
git diff --cached --check
git commit -m "Initial release"
git remote add origin git@github.com:OWNER/REPOSITORY.git
git push -u origin main
```

把 `OWNER/REPOSITORY` 替换成实际的 GitHub 用户名和仓库名。

如果本机还没有 GitHub SSH 密钥：

```powershell
ssh-keygen -t ed25519 -C "your-github-email@example.com"
Get-Content $HOME\.ssh\id_ed25519.pub
```

将公钥添加到 GitHub 的 `Settings -> SSH and GPG keys`，然后验证：

```powershell
ssh -T git@github.com
```

## 2. 准备 Ubuntu 服务器

服务器必须已经完成 `DEPLOY_UBUNTU.md` 中的首次部署，并且 `/opt/office-asset-mgmt` 是该 GitHub 仓库的工作副本。

建议创建专用发布用户：

```bash
sudo useradd --create-home --shell /bin/bash officeasset-deploy
sudo usermod -aG officeasset officeasset-deploy
sudo chown -R officeasset-deploy:officeasset /opt/office-asset-mgmt
sudo chmod -R u+rwX,g+rX,o-rwx /opt/office-asset-mgmt
```

给发布用户配置 GitHub 仓库的只读 Deploy key：

```bash
sudo -u officeasset-deploy mkdir -p /home/officeasset-deploy/.ssh
sudo -u officeasset-deploy ssh-keygen -t ed25519 \
  -f /home/officeasset-deploy/.ssh/id_ed25519 \
  -N "" \
  -C "officeasset-deploy"
sudo cat /home/officeasset-deploy/.ssh/id_ed25519.pub
```

将输出的公钥添加到 GitHub 仓库的 `Settings -> Deploy keys`，只勾选 `Allow read access`。然后在服务器上执行：

```bash
sudo -u officeasset-deploy ssh-keyscan github.com \
  >> /home/officeasset-deploy/.ssh/known_hosts
sudo chmod 700 /home/officeasset-deploy/.ssh
sudo chmod 600 /home/officeasset-deploy/.ssh/id_ed25519
sudo chmod 644 /home/officeasset-deploy/.ssh/known_hosts
sudo -u officeasset-deploy git -C /opt/office-asset-mgmt fetch origin main
```

允许发布用户只重启本项目服务。先用 `command -v systemctl` 确认路径，Ubuntu 通常为 `/usr/bin/systemctl`：

```bash
sudo visudo -f /etc/sudoers.d/officeasset-deploy
```

写入：

```text
officeasset-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart office-asset-mgmt, /usr/bin/systemctl is-active office-asset-mgmt
```

## 3. 配置 GitHub Actions Secrets

在 GitHub 仓库打开 `Settings -> Secrets and variables -> Actions`，创建以下 Repository secrets：

| Secret | 内容 |
| --- | --- |
| `DEPLOY_HOST` | Ubuntu 服务器 IP 或域名 |
| `DEPLOY_PORT` | SSH 端口；默认 `22` |
| `DEPLOY_USER` | `officeasset-deploy` |
| `DEPLOY_PATH` | 默认 `/opt/office-asset-mgmt` |
| `DEPLOY_BRANCH` | 默认 `main` |
| `DEPLOY_PRIVATE_KEY` | 能登录 Ubuntu 的 SSH 私钥全文 |
| `DEPLOY_KNOWN_HOSTS` | 服务器 SSH 主机公钥全文 |

`DEPLOY_PRIVATE_KEY` 对应的公钥必须写入服务器：

```text
/home/officeasset-deploy/.ssh/authorized_keys
```

在一台可信的管理机上获取 `DEPLOY_KNOWN_HOSTS`，并核对服务器指纹后再保存：

```bash
ssh-keyscan -H SERVER_HOST
```

不要把 `.env`、MySQL 密码、SSH 私钥或数据库备份放入 GitHub Secrets 以外的仓库文件。

## 4. 验证自动发布

提交并推送任意代码更新：

```powershell
cd D:\数据库\office-asset-management-github
git add .
git diff --cached --check
git commit -m "Update application"
git push
```

在 GitHub 的 `Actions` 页面应看到 `Verify and publish`。验证完成后，服务器上的以下命令应返回 HTTP 200：

```bash
curl http://127.0.0.1:8000/api/health
sudo systemctl status office-asset-mgmt
```

数据库结构变更不会被自动执行。涉及 SQL 迁移时，请先备份数据库，再在服务器上按版本说明手动执行对应脚本。

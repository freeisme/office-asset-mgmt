# 安全整改清单

本文档记录本次针对办公资产管理系统进行的网络安全检查、已修复问题和剩余运维注意事项。

## 已修复

### 1. 登录页隐藏状态失效

- 原因：`.app-shell { display: flex }` 覆盖了 `hidden` 属性的默认隐藏行为。
- 风险：会话过期后，旧主页仍可能出现在登录页下方，造成状态混淆。
- 修复：增加全局 `[hidden] { display: none !important; }`。

### 2. 第三方字体外联

- 原因：样式表通过外部 `@import` 加载第三方字体。
- 风险：客户端加载页面时会向无关外部站点发起请求，增加隐私泄露和供应链依赖。
- 修复：移除 `web/styles.css` 中的外部字体导入，改用本机字体回退链。

### 3. 缺少统一浏览器安全响应头

- 风险：未设置安全响应头时，点击劫持、资源类型误判和部分跨源风险更难防护。
- 修复：后端统一增加：
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: same-origin`
  - `Permissions-Policy`
  - `Cross-Origin-Opener-Policy`
  - `Cross-Origin-Resource-Policy`

### 4. 健康检查泄露数据库网络信息

- 原因：未登录的 `/api/health` 以前返回数据库名称、主机和端口。
- 风险：为未认证访问者提供内部网络拓扑和服务指纹。
- 修复：健康检查现在只返回：
  - `ok`
  - `databaseProbe`
  - `requiredTables`
  - `requiredTableCount`

### 5. JSON 请求体没有大小限制

- 原因：API 直接按客户端提供的 `Content-Length` 读取请求体。
- 风险：攻击者可以发送超大 JSON 请求消耗应用内存和线程。
- 修复：增加 `MAX_REQUEST_BODY_BYTES`，默认 8 MB、上限 64 MB，超限返回 HTTP 413。

### 6. 内部异常信息回显

- 原因：未捕获异常、数据库执行错误和更新服务连接错误以前会把原始错误返回给客户端。
- 风险：可能暴露文件路径、数据库连接信息、命令行错误或内部服务地址。
- 修复：数据库执行/解析失败归类为内部错误；客户端只收到通用错误码，详细信息保留在服务器日志中。

### 7. 修改密码后旧会话仍然有效

- 原因：修改密码或管理员重置密码时，只更新密码哈希，没有撤销已有 `auth_session`。
- 风险：已经泄露的旧会话令牌在密码修改后仍可继续访问系统。
- 修复：用户修改自己的密码时保留当前会话并撤销其他会话；管理员重置密码时撤销目标账号的旧会话，重置自己的密码时保留当前会话。

## 已确认的现有防护

- 写接口要求登录、角色权限和 CSRF Token。
- 会话 Cookie 使用 `HttpOnly`、`SameSite=Lax`。
- 密码使用 `scrypt` 哈希，不保存明文。
- 登录失败达到阈值后会临时锁定账号。
- 修改密码或重置密码会撤销相关旧会话。
- 备份下载要求管理员权限、CSRF Token 和当前密码。
- 备份路径会限制在 `BACKUP_DIR` 内，防止路径穿越。
- Gitea Webhook 使用 HMAC 签名校验。
- 更新控制接口使用独立控制令牌。
- 应用容器默认不发布 MySQL 端口。

## 仍需落实的生产运维要求

这些项目依赖服务器配置，不能只通过仓库代码解决：

1. 生产环境使用 HTTPS，并设置 `AUTH_COOKIE_SECURE=true`。
2. 只允许必要网段访问应用端口。
3. Gitea Webhook 端口不要暴露到公网或无关局域网。
4. 应用使用独立 MySQL 账号，禁止使用 root 连接 Web 服务。
5. `.env`、备份文件、Webhook Secret、更新控制令牌和 SSH 私钥不得进入 Git。
6. Docker、Gitea、MySQL 和 Ubuntu 主机按安全补丁周期更新。
7. 备份保存到服务器之外，并定期执行恢复演练。

## 验证清单

```text
[ ] 页面源码不再包含 fonts.loli.net
[ ] /api/health 不再返回数据库主机和端口
[ ] 超大 JSON 请求返回 413
[ ] 未捕获异常不回显内部错误详情
[ ] 修改密码后其他旧会话失效
[ ] HTTP 响应包含 CSP、X-Frame-Options、nosniff 等安全头
[ ] 未登录不能读取 /api/state
[ ] 写接口缺少 CSRF Token 时返回 403
[ ] viewer 不能执行管理员接口
[ ] 备份下载不能绕过当前密码校验
[ ] Webhook 无效签名返回 401
[ ] Gitea main 已同步安全整改提交
```

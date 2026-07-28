# Shorten Your URL

一个可私有化部署的多账号短链接服务。默认使用容器内置 SQLite，不依赖 MySQL 等外部服务。

## 功能

- Docker Compose 一条命令启动，数据库与应用密钥持久化在 Docker Volume 中
- 管理员创建/停用其他账号（不提供公开注册）
- 短链接按创建账号严格隔离；账号只能查看、编辑、删除自己的链接
- scrypt 密码哈希、密码复杂度检查、账号指数锁定、IP 持久化限流
- CSRF 防护、安全响应头、会话版本失效、可信代理显式配置
- 跳转模式默认启用；高风险代理模式默认关闭，并带内网地址、超时和响应大小限制
- 非 root、只读文件系统、移除 Linux capabilities 的最小权限容器

## 快速部署

服务器只需安装 Docker Engine 与 Docker Compose 插件：

```bash
git clone <你的仓库地址> shorten-your-url
cd shorten-your-url
cp .env.example .env
```

编辑 `.env`，至少将 `ADMIN_PASSWORD` 改为安全密码，然后启动：

```bash
docker compose up -d --build
```

访问 `http://服务器IP:5000/login`，使用 `.env` 中的 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 登录。初始密码只在数据库为空的第一次启动时使用，后续修改 `.env` 不会覆盖已有管理员密码。

检查运行状态：

```bash
docker compose ps
docker compose logs -f shortener
```

停止服务不会删除数据：

```bash
docker compose down
```

> 不要执行 `docker compose down -v`，除非确认要永久删除数据库和应用密钥。

## HTTPS 反向代理

生产环境建议由 Caddy、Nginx 或 Traefik 提供 HTTPS。代理到 `127.0.0.1:5000` 时，建议在 `.env` 中设置：

```dotenv
BIND_ADDRESS=127.0.0.1
PUBLIC_BASE_URL=https://s.example.com
COOKIE_SECURE=true
TRUST_PROXY_COUNT=1
TRUSTED_HOSTS=s.example.com
```

只将 `TRUST_PROXY_COUNT` 设置为实际可信代理层数。应用不会在未配置时信任客户端伪造的 `X-Forwarded-For`。

## 账号管理与隔离

首次启动创建的账号是管理员。登录后进入“账号管理”创建普通账号、停用账号或重置密码。系统没有 `/register` 路由。

链接的所有管理查询都同时检查 `owner_id`。管理员也只能在链接面板管理自己创建的链接；管理员权限只额外提供账号管理能力。

## 登录安全策略

- 密码至少 12 位，且包含大小写字母、数字、特殊字符中的至少三类
- 密码使用 Werkzeug scrypt 哈希，不保存或记录明文密码
- 单账号连续失败 5 次后锁定 15 分钟，继续失败按指数延长，最长 4 小时
- 单 IP 15 分钟内失败 20 次后限流；记录位于 SQLite，多 Worker 与容器重启后仍生效
- 不存在的用户名也执行同等成本密码计算，并使用统一错误信息，降低账号枚举风险
- 管理员停用账号或重置密码后，该账号现存会话立即失效

## 数据与备份

SQLite 数据库和自动生成的会话密钥位于 `shortener_data` Volume。在线备份建议使用 SQLite 的备份命令：

```bash
docker compose exec shortener python -c "import sqlite3; s=sqlite3.connect('/data/shortener.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
docker cp $(docker compose ps -q shortener):/data/backup.db ./shortener-backup.db
```

恢复前请先停止容器，并同时保留 `/data/.secret_key`；更换密钥会使现有登录会话失效。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `ADMIN_USERNAME` | `admin` | 首次启动的管理员用户名 |
| `ADMIN_PASSWORD` | 无 | 首次启动必填的强密码 |
| `PORT` | `5000` | 宿主机监听端口 |
| `BIND_ADDRESS` | `0.0.0.0` | 宿主机绑定地址 |
| `PUBLIC_BASE_URL` | 自动识别 | 对外短链接根地址 |
| `COOKIE_SECURE` | `false` | HTTPS 部署时设为 `true` |
| `TRUST_PROXY_COUNT` | `0` | 可信反向代理层数 |
| `TRUSTED_HOSTS` | 空 | 允许的 Host，多个值用逗号分隔 |
| `ENABLE_PROXY` | `false` | 是否开启代理模式 |
| `WEB_WORKERS` | `2` | Gunicorn Worker 数量 |
| `SECRET_KEY` | 自动生成 | 可选；若设置需至少 32 字符 |

## 本地开发

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
ADMIN_PASSWORD='Local-Test_2026!' python app.py
```

Windows PowerShell：

```powershell
$env:ADMIN_PASSWORD='Local-Test_2026!'
python app.py
```

## 从旧版升级

本版本的数据模型增加了账号归属字段，并由 MySQL 改为 SQLite，因此不会自动读取旧版 MySQL 数据。已有生产数据应先备份 MySQL，再编写一次性迁移或人工导入；不要直接销毁原数据库。全新服务器部署无需外部数据库。

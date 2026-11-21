# Shorten Your URL

一个可私有化部署的多账号短链接服务。默认使用容器内置 SQLite，不依赖 MySQL 等外部服务。

## 功能

- Docker Compose 一条命令启动，数据库与应用密钥原子化持久化在 Docker Volume 中
- 管理员创建/停用其他账号（不提供公开注册）
- 短链接按创建账号严格隔离；账号只能查看、编辑、删除自己的链接
- scrypt 密码哈希、密码复杂度检查、账号指数锁定、IP 持久化限流
- CSRF 防护、COOP/CORP 浏览上下文隔离、安全响应头、会话版本失效、可信代理显式配置
- 跳转模式默认启用；代理模式默认关闭，内置底层 Socket 公网 IP 直连校验（防 DNS Rebinding）、HMAC 签名代理会话、Service Worker 阻断、跨源重定向源追踪及隔离 Cookie 桥接
- 支持 `PROXY_PUBLIC_BASE_URL` 独立子域名物理隔离代理流量与管理后台
- 非 root、只读文件系统、移除 Linux capabilities 的最小权限容器

## 快速部署

服务器只需安装 Docker Engine 与 Docker Compose 插件：

```bash
git clone <你的仓库地址> shorten-your-url
cd shorten-your-url
cp .env.example .env
```

编辑 `.env`，至少将 `ADMIN_PASSWORD` 改为安全密码（若不使用 Nginx 反代而需直连测试，请将 `BIND_ADDRESS=0.0.0.0` 且 `TRUST_PROXY_COUNT=0`），然后启动：

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

## HTTPS 反向代理与 Nginx 推荐配置模版

生产环境建议将容器绑定在本机回环地址 `127.0.0.1:5000`，由前置 Nginx 终止 TLS 并转发流量。

### 1. 配套 `.env` 参数配置

启用代理模式时，强烈建议准备两个子域名（例如 `s.example.com` 用于管理后台与常规 302 短链，`p.example.com` 专用于代理模式渲染），彻底实现浏览器同源物理隔离：

```dotenv
BIND_ADDRESS=127.0.0.1
PORT=5000
PUBLIC_BASE_URL=https://s.example.com
PROXY_PUBLIC_BASE_URL=https://p.example.com
COOKIE_SECURE=true
TRUST_PROXY_COUNT=1
TRUSTED_HOSTS=s.example.com,p.example.com
ENABLE_PROXY=true
PROXY_ADMIN_ONLY=true
PROXY_MAX_MB=50
PROXY_MAX_REQUEST_MB=20
```

> 安全要点：仅将 `TRUST_PROXY_COUNT` 设置为实际经过的可信反向代理层数（单层 Nginx 设为 `1`；若 Nginx 前方还有 Cloudflare 等可信 CDN 且已在 Nginx 层做真实 IP 还原，请按最终附加到 `X-Forwarded-For` 的可信层数配置），并保持 `BIND_ADDRESS=127.0.0.1` 防止外部绕过 Nginx 直连容器伪造请求头。

### 2. 通用 Nginx 配置模版（双域名安全隔离推荐方案）

将以下模版保存为独立的站点配置文件（如 `conf.d/shortener.conf`），并将 `s.example.com`、`p.example.com` 及证书路径替换为实际值：

```nginx
upstream shortener_backend {
    server 127.0.0.1:5000 max_fails=3 fail_timeout=10s;
    keepalive 32;
}

# HTTP 统一保留 ACME 证书续签验证并跳转 HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name s.example.com p.example.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# 主域名：承载管理后台、登录鉴权与常规 302 跳转短链
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name s.example.com;

    ssl_certificate     /etc/letsencrypt/live/s.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/s.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:ShortenerSSL:10m;
    ssl_session_timeout 1d;

    # 管理后台与短链创建请求体较小，限制为 2MB 即可
    client_max_body_size 2m;

    location / {
        # 注意：proxy_pass 末尾切勿添加 "/"，确保原样透传未解码 URI（如 %5Btoken%5D、%2F）
        proxy_pass http://shortener_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;

        proxy_connect_timeout 5s;
        proxy_send_timeout    30s;
        proxy_read_timeout    30s;
    }
}

# 独立代理子域名：仅承载代理模式页面与子资源，物理隔离管理会话 Cookie
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name p.example.com;

    ssl_certificate     /etc/letsencrypt/live/p.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/p.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:ShortenerSSL:10m;
    ssl_session_timeout 1d;

    # 对齐 .env 中的 PROXY_MAX_REQUEST_MB（如 20MB，适当留出头部余量）
    client_max_body_size 25m;

    # 在网关层前置屏蔽后台路径，与应用层隔离形成纵深防御
    location ~* ^/(?:login|logout|admin)(?:/|$) {
        return 404;
    }

    location / {
        # 阻断浏览器 Service Worker 脚本注册请求
        if ($http_service_worker != "") {
            return 403;
        }

        # 切勿在末尾添加 "/"，防止 Nginx 二次解码破坏上游签名参数与 SPA 动态路由路径
        proxy_pass http://shortener_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;

        # 关闭代理缓冲以支持大体积 WASM/媒体流式传输及 SSE 实时事件流
        proxy_buffering         off;
        proxy_request_buffering off;

        # 与容器 WEB_TIMEOUT（默认 120s）保持一致
        proxy_connect_timeout 10s;
        proxy_send_timeout    60s;
        proxy_read_timeout    120s;
    }
}
```

### 3. 单域名精简方案（仅使用 302 跳转模式时）

如果不需要开启代理模式（保持默认 `ENABLE_PROXY=false` 且 `PROXY_PUBLIC_BASE_URL` 留空），只需保留上方配置中的 `upstream shortener_backend`、`80` 跳转块（仅填 `s.example.com`）以及 `s.example.com` 的 `443` `server` 块即可，无需申请第二个子域名证书。

> 兼容性提示：若服务器上的 Nginx 版本低于 `1.25.1`，请将配置中的 `listen 443 ssl;` + `http2 on;` 合并替换为旧版语法 `listen 443 ssl http2;`。

修改完成后执行语法检查并平滑重载 Nginx：

```bash
nginx -t && nginx -s reload
```

## 账号管理与隔离

首次启动创建的账号是管理员。登录后进入“账号管理”创建普通账号、停用账号或重置密码。系统没有 `/register` 路由。

链接的所有管理查询都同时检查 `owner_id`。默认仅管理员可创建代理模式短链（可通过 `PROXY_ADMIN_ONLY=false` 调整）。

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
| `BIND_ADDRESS` | `127.0.0.1` | 宿主机绑定地址（无反代直连时改为 `0.0.0.0`） |
| `PUBLIC_BASE_URL` | 自动识别 | 对外主管理与短链接根地址 |
| `PROXY_PUBLIC_BASE_URL` | 空 | 独立代理渲染根地址（如 `https://p.example.com`） |
| `COOKIE_SECURE` | `false` | HTTPS 部署时设为 `true` |
| `TRUST_PROXY_COUNT` | `0` | 可信反向代理层数 |
| `TRUSTED_HOSTS` | 空 | 允许的 Host，多个值用逗号分隔 |
| `ENABLE_PROXY` | `false` | 是否开启代理模式 |
| `PROXY_ADMIN_ONLY` | `true` | 是否仅允许管理员创建/编辑代理短链 |
| `ENABLE_PROXY_COOKIES` | `true` | 是否开启命名空间隔离的上游会话 Cookie 桥接 |
| `PROXY_ALLOW_CUSTOM_PORTS` | `false` | 是否允许代理目标使用非 80/443 端口 |
| `PROXY_MAX_MB` | `50` | 代理模式单响应最大允许体积（MB） |
| `PROXY_MAX_REQUEST_MB` | `20` | 代理模式单请求体最大允许体积（MB） |
| `PROXY_REWRITE_MAX_MB` | `25` | HTML/CSS 服务端重写最大缓冲体积（MB） |
| `PROXY_MAX_SSE_STREAMS` | `6` | 单 Worker 最大并发 SSE 流连接数 |
| `WEB_WORKERS` | `2` | Gunicorn Worker 数量 |
| `WEB_THREADS` | `8` | 每个 Gunicorn Worker 的并发线程数 |
| `WEB_TIMEOUT` | `120` | Gunicorn 请求超时秒数 |
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

运行单元测试：

```bash
python -m unittest discover -s tests -v
```

# 🔗 URL Shortener (可私有化部署的短链接服务)

<img width="2048" height="1502" alt="image" src="https://github.com/user-attachments/assets/08015c5a-0595-4785-8f76-24c1aec8b667" />

## 简介

本项目是一个基于 **Python Flask** 搭建的、带管理后台的短链接服务（URL Shortener）。它支持将任意长链接转换为简短、易于分享的短码，并提供管理员登录界面进行链接管理、添加备注、自定义短码和查看点击量等功能。

### 🚀 技术栈

  * **后端:** Python 3.x, Flask, Flask-SQLAlchemy, Flask-Login
  * **数据库:** MySQL
  * **Web 服务器:** Gunicorn (WSGI) + Nginx (反向代理)
  * **部署环境:** Ubuntu 22.04 LTS

-----

## 🛠️ 快速部署指南

本指南假设您已拥有一个 **Ubuntu 22.04 VPS**，并已安装 **Nginx**, **MySQL** 和 **Python 3.10+** 环境。

### 步骤一：环境准备与依赖安装

1.  **克隆项目并进入目录:**

    ```bash
    git clone [您的 GitHub 仓库地址] url_shortener
    cd url_shortener
    ```

2.  **创建并激活虚拟环境:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **安装 Python 依赖:**

    ```bash
    pip install Flask Flask-SQLAlchemy PyMySQL Flask-Login Gunicorn cryptography
    ```

### 步骤二：数据库配置 (MySQL)

您需要为应用程序创建一个专用的数据库和用户。

1.  **登录 MySQL** (以 root 用户为例):

    ```bash
    sudo mysql
    ```

2.  **创建数据库和用户:**

    ```sql
    -- 替换 'shortener_user' 和 'your_strong_password'
    CREATE DATABASE url_shortener_db;
    CREATE USER 'shortener_user'@'localhost' IDENTIFIED BY 'your_strong_password';
    GRANT ALL PRIVILEGES ON url_shortener_db.* TO 'shortener_user'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;
    ```

    ⚠️ **重要：** 请将 **`your_strong_password`** 记录下来。

### 步骤三：配置应用并初始化数据库

1.  **修改 `app.py` 数据库连接:**
    编辑 `app.py` 文件，更新 `SQLALCHEMY_DATABASE_URI` 为您在步骤二中设置的凭证：

    ```python
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://shortener_user:your_strong_password@localhost/url_shortener_db'
    ```

2.  **运行初始化脚本:**
    在虚拟环境内运行 `app.py` 一次，以创建数据库表并生成初始管理员账户。

    ```bash
    python app.py
    # 看到 Flask 启动提示和管理员信息后，按 Ctrl + C 停止。
    ```

    记下终端输出的初始管理员用户名（`admin` 或您自定义的）和密码。

### 步骤四：配置 Gunicorn 守护进程 (Systemd)

为了让应用在后台持续运行，我们使用 Systemd 进行管理。

1.  **创建服务文件:**

    ```bash
    sudo nano /etc/systemd/system/url_shortener.service
    ```

    粘贴以下内容 (请将 `root` 和 `/root/url_shortener` 替换为您实际的用户名和项目路径)：

    ```ini
    [Unit]
    Description=Gunicorn instance for shortener
    After=network.target

    [Service]
    User=root #如果提示用户权限问题，可将此注释掉
    Group=root #如果提示用户权限问题，可将此注释掉
    WorkingDirectory=/root/url_shortener
    Environment="PATH=/root/url_shortener/venv/bin"
    ExecStart=/root/url_shortener/venv/bin/gunicorn --workers 3 --bind unix:/tmp/shortener.sock app:app 

    [Install]
    WantedBy=multi-user.target
    ```

2.  **启动服务:**

    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start url_shortener
    sudo systemctl enable url_shortener
    sudo systemctl status url_shortener
    ```

    确认服务状态为 `active (running)`。

### 步骤五：配置 Nginx 和 SSL (HTTPS)

假设您已使用 Certbot 为您的域名 `xxx.com` 获取了证书，且证书路径为 `/etc/letsencrypt/live/xxx.com/`。

1.  **创建或编辑 Nginx 配置文件** (`/etc/nginx/sites-available/xxx.com`):
    确保配置包含了 HTTP 到 HTTPS 的重定向，并将 HTTPS 流量转发到 Gunicorn 的 Unix Socket。

    ```nginx
    server {
        listen 80;
        listen [::]:80;
        server_name xxx.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name xxx.com;

        ssl_certificate /etc/letsencrypt/live/xxx.com/fullchain.pem; 
        ssl_certificate_key /etc/letsencrypt/live/xxx.com/privkey.pem;

        include /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

        location / {
            proxy_pass http://unix:/tmp/shortener.sock; 
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    ```

2.  **启用配置并重启 Nginx:**

    ```bash
    sudo ln -s /etc/nginx/sites-available/xxx.com /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl reload nginx
    ```

-----

## 🌍 使用方法

  * **短链接访问:** `https://xxx.com/您的短码` (例如：`https://xxx.com/clash`)
  * **管理后台:** `https://xxx.com/login`
      * 使用初始管理员账户登录后，即可创建、编辑和删除短链接。
      * **强烈建议** 登录后立即修改管理员密码。

-----

## 🛡️ 安全与维护

1.  **修改初始密码:** 首次登录后，请通过 SQL 命令或实现页面功能来修改初始管理员密码。
2.  **数据库备份:** 定期备份 `url_shortener_db` 数据库。
3.  **Certbot 续期:** Certbot 应该已经配置自动续期，但请定期检查续期任务是否正常工作。

## 联系开发者
mailto: do@eiai.studio

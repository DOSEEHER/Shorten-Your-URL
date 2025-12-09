# 🔗 Shorten Your URL / URL Shortener (可私有化部署的短链接服务)

<img width="2181" height="1826" alt="image" src="https://github.com/user-attachments/assets/d6e486b7-3c07-4b97-8ecb-b2e9a7f93761" />

## 简介

本项目是一个功能完备的、基于 **Python Flask** 搭建的短链接服务（URL Shortener）。它支持将任意长链接转换为简短、易于分享的短码，并提供安全的管理员登录界面进行全面的链接管理。

### 🚀 核心功能与亮点

  * **双模式支持:** 支持 **跳转模式 (Redirect)** 和 **代理模式 (Proxying)**，用户在创建链接时可自行选择，以兼顾速度和隐私。
      * **跳转模式:** 使用 302 状态码，跳转速度快，但目标 URL 在网络请求中可见。
      * **代理模式:** 地址栏保持短链接不变，内容由后端获取并返回，可**彻底隐藏原始长链接**，适用于配置或静态文件共享。
  * **完整的管理功能:** 支持新建链接、自定义短码、**编辑链接属性**、**删除链接** 和查看点击量。
  * **安全部署:** 使用 **Systemd Environment** 变量安全地隔离数据库凭证和应用密钥。

### ⚙️ 技术栈

  * **后端:** Python 3.x, Flask, Flask-SQLAlchemy, Flask-Login, Requests
  * **数据库:** MySQL
  * **Web 服务器:** Gunicorn (WSGI) + Nginx (反向代理)
  * **部署环境:** Ubuntu 22.04 LTS

-----

## 🛠️ 快速部署指南

本指南侧重于使用 **Git** 和 **Systemd** 进行安全部署和更新。

### 步骤一：环境准备与依赖安装

1.  **克隆或同步项目到 VPS:**

    ```bash
    git clone [您的 GitHub 仓库地址] Shorten-Your-URL
    cd Shorten-Your-URL
    ```

2.  **创建并激活虚拟环境:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **安装所有依赖:**

    ```bash
    pip install Flask Flask-SQLAlchemy PyMySQL Flask-Login Gunicorn cryptography requests
    ```

### 步骤二：数据库配置 (MySQL)

1.  **登录 MySQL** (以 root 用户为例):

    ```bash
    sudo mysql
    ```

2.  **创建数据库和用户:**

    ```sql
    -- 替换 'shortener_user' 和 'YOUR_DB_PASSWORD'
    CREATE DATABASE url_shortener_db;
    CREATE USER 'shortener_user'@'localhost' IDENTIFIED BY 'YOUR_DB_PASSWORD';
    GRANT ALL PRIVILEGES ON url_shortener_db.* TO 'shortener_user'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;
    ```

    ⚠️ **重要：** 请记录 `YOUR_DB_PASSWORD`，用于下一步配置。

3.  **初始化数据库表结构和管理员账户:**

    ```bash
    # 确保 app.py 中的 DB_USER, DB_NAME 设置正确（如果代码中有 default 值，此步应成功）
    python app.py
    # 记下终端输出的初始管理员用户名和密码 (如：admin/123456)。完成后 Ctrl + C 停止。
    ```

### 步骤三：Systemd 安全配置（环境变量）

我们通过 Systemd 设置环境变量来隔离敏感信息。

1.  **创建服务文件** (`/etc/systemd/system/url_shortener.service`):

    ```bash
    sudo nano /etc/systemd/system/url_shortener.service
    ```

    粘贴以下内容（请替换 **路径** 和 **敏感变量**）：

    ```ini
    [Unit]
    Description=Gunicorn instance for shortener
    After=network.target

    [Service]
    User=root  #如果出现权限提示，可尝试注释掉本行
    Group=root  #如果出现权限提示，可尝试注释掉本行
    WorkingDirectory=/root/Shorten-Your-URL

    # 🚨 关键：在此处设置您的数据库密码和应用密钥
    Environment="DB_PASS=YOUR_DB_PASSWORD"
    Environment="SECRET_KEY=YOUR_APPLICATION_SECRET_KEY" 
    Environment="DB_USER=shortener_user"
    Environment="DB_NAME=url_shortener_db"

    # 执行启动前，自动检查并安装依赖（增强稳定性）
    ExecStartPre=/usr/bin/python3 -m venv venv || true
    ExecStart=/root/Shorten-Your-URL/venv/bin/gunicorn --workers 3 --bind unix:/tmp/shortener.sock app:app

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

### 步骤四：Nginx 配置和 SSL

1.  **确保 Nginx 配置** (`/etc/nginx/sites-available/你的域名.conf`) 已包含 Certbot 证书路径和 HTTP 到 HTTPS 的重定向。
2.  **确保 `location /` 块将流量转发到 Unix Socket:**
    ```nginx
    location / {
        proxy_pass http://unix:/tmp/shortener.sock; 
        # ... (其他 proxy_set_header)
    }
    ```
3.  **启用配置并重启 Nginx:**
    ```bash
    sudo ln -s /etc/nginx/sites-available/你的域名.conf /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl reload nginx
    ```

-----

## 🌍 使用方法

  * **管理后台:** `https://你的域名/login`
  * **短链接访问:** `https://你的域名/您的短码`
  * **初始管理员:** `admin` / `初始密码` (请在数据库中修改或登录后自行更新用户名和密码)。

import random
import string
import requests
import os
import time
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 配置 ---
# 从环境变量中读取数据库凭证
DB_USER = os.environ.get('DB_USER', 'shortener_user')
DB_PASS = os.environ.get('DB_PASS', 'default_secret') # ⚠️ 生产环境必须设置
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_NAME = os.environ.get('DB_NAME', 'url_shortener_db')

# 使用读取到的变量构建连接字符串
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'

# ⚠️ 同样，修改 SECRET_KEY 从环境变量中读取
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_insecure_key')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # 未登录时重定向的视图函数

# --- 数据库模型 ---

class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    short_code = db.Column(db.String(50), unique=True, nullable=False)
    original_url = db.Column(db.String(2048), nullable=False)
    note = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    clicks = db.Column(db.Integer, default=0)
    mode = db.Column(db.String(10), default='redirect', nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- 首页 ---

@app.route('/')
def index():
    
    return render_template('index.html') 

# --- 登录管理器回调 ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 辅助函数 ---

def generate_unique_short_code(length=6):
    """生成唯一的随机短码"""
    characters = string.ascii_letters + string.digits
    while True:
        code = ''.join(random.choice(characters) for i in range(length))
        if Link.query.filter_by(short_code=code).first() is None:
            return code

# --- 路由：短链接跳转 ---

@app.route('/<short_code>')
def redirect_to_url(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()
    link.clicks += 1
    db.session.commit()
    # 确保 URL 包含协议头
    original_url = link.original_url
    if not original_url.startswith(('http://', 'https://')):
        original_url = 'http://' + original_url

    # --- 核心逻辑：根据模式判断执行代理还是重定向 ---
    if link.mode == 'proxy':
        # 执行代理模式
        try:
            # stream=True 是为了高效处理大文件
            response = requests.get(original_url, stream=True)
            
            # 将原始响应头原样传回给客户端（注意：要去除 Content-Length 以防冲突）
            headers = [(name, value) for name, value in response.headers.items() 
                       if name.lower() not in ('content-encoding', 'content-length')]
                       
            return response.content, response.status_code, headers
            
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error proxying URL {original_url}: {e}")
            return "代理目标 URL 无法访问或连接错误。", 500
    
    else: # link.mode == 'redirect' 或其他任何值
        # 执行重定向模式
        return redirect(original_url, code=302)

# --- 登录安全防护：防暴破机制 ---
# 记录每个 IP 的失败尝试时间戳，格式：{ ip: [timestamp1, timestamp2, ...] }
FAILED_LOGIN_ATTEMPTS = defaultdict(list)
BLOCK_DURATION = 300  # 限制时间 5 分钟
MAX_FAILED_ATTEMPTS = 5 # 最大失败次数

def get_client_ip():
    # 优先从 Nginx 传入的 X-Forwarded-For 和 X-Real-IP 中获取真实 IP
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.headers.get('X-Real-IP', request.remote_addr)

def check_ip_block(ip):
    now = time.time()
    # 清理已过期的失败记录（超过 5 分钟的）
    FAILED_LOGIN_ATTEMPTS[ip] = [t for t in FAILED_LOGIN_ATTEMPTS[ip] if now - t < BLOCK_DURATION]
    return len(FAILED_LOGIN_ATTEMPTS[ip]) >= MAX_FAILED_ATTEMPTS

def record_failed_login(ip):
    FAILED_LOGIN_ATTEMPTS[ip].append(time.time())
    # 增加登录失败的防御性延迟，减缓暴力破解工具的速度
    time.sleep(2.0)

def clear_failed_login(ip):
    if ip in FAILED_LOGIN_ATTEMPTS:
        del FAILED_LOGIN_ATTEMPTS[ip]

# --- 路由：登录 ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    ip = get_client_ip()

    # 检查当前 IP 是否因为尝试失败次数过多而被暂时封禁
    if check_ip_block(ip):
        flash('由于登录失败次数过多，该 IP 已被临时锁定。请 5 分钟后再试。', 'danger')
        return render_template('login.html'), 429

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            clear_failed_login(ip) # 登录成功，清除失败记录
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            record_failed_login(ip) # 记录失败并触发 2 秒延迟
            flash('用户名或密码错误。', 'danger')

    # 简单的登录表单，你需要在 templates/login.html 中实现它
    return render_template('login.html')

# --- 路由：登出 ---

@app.route('/logout')
@login_required
def logout():
    """处理用户登出"""
    logout_user()
    flash('您已成功退出登录。', 'info')
    return redirect(url_for('login')) 
    # 或者重定向到主页，如果将来有主页的话

# --- 路由：管理后台 ---

@app.route('/admin')
@login_required
def admin_dashboard():
    links = Link.query.order_by(Link.created_at.desc()).all()
    # 简单的管理页面，你需要在 templates/admin.html 中实现它
    return render_template('admin.html', links=links)

# --- 路由：创建新链接 ---

@app.route('/admin/create', methods=['POST'])
@login_required
def create_link():
    original_url = request.form.get('original_url')
    custom_code = request.form.get('custom_code')
    note = request.form.get('note', '')
    mode = request.form.get('mode', 'redirect')

    if not original_url:
        flash('长链接不能为空。', 'danger')
        return redirect(url_for('admin_dashboard'))

    if custom_code:
        # 检查自定义短码是否已存在
        if Link.query.filter_by(short_code=custom_code).first():
            flash(f'短码 "{custom_code}" 已被占用。', 'danger')
            return redirect(url_for('admin_dashboard'))
        short_code = custom_code
    else:
        short_code = generate_unique_short_code()

    new_link = Link(
        original_url=original_url,
        short_code=short_code,
        note=note,
        mode=mode
    )
    db.session.add(new_link)
    db.session.commit()
    flash(f'短链接创建成功! 短码: {short_code}', 'success')
    return redirect(url_for('admin_dashboard'))

# --- 路由：编辑链接 (GET and POST) ---
@app.route('/admin/edit/<short_code>', methods=['GET', 'POST'])
@login_required
def edit_link(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()

    if request.method == 'POST':
        # 1. 更新长链接和备注
        link.original_url = request.form.get('original_url')
        link.note = request.form.get('note', '')
        # 2. 🚨 关键：更新 mode 字段
        link.mode = request.form.get('mode', 'redirect') 
        
        if not link.original_url:
            flash('长链接不能为空。', 'danger')
            return redirect(url_for('edit_link', short_code=short_code))

        db.session.commit()
        flash(f'短码 "{short_code}" 已成功更新!', 'success')
        return redirect(url_for('admin_dashboard'))

    # GET 请求：显示编辑表单
    return render_template('edit.html', link=link)

    # GET 请求：显示编辑表单
    return render_template('edit.html', link=link)


# --- 路由：删除链接 (POST ONLY) ---
@app.route('/admin/delete/<short_code>', methods=['POST'])
@login_required
def delete_link(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()
    
    db.session.delete(link)
    db.session.commit()
    flash(f'短码 "{short_code}" 已被删除。', 'info')
    return redirect(url_for('admin_dashboard'))


# --- 路由：修改账户信息 ---
@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_username = request.form.get('new_username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # 验证当前密码是否正确
        if not current_user.check_password(current_password):
            flash('当前密码错误，无法保存更改。', 'danger')
            return redirect(url_for('profile'))

        # 如果修改用户名
        if new_username and new_username != current_user.username:
            # 检查用户名是否重复
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != current_user.id:
                flash(f'用户名 "{new_username}" 已存在，请使用其他用户名。', 'danger')
                return redirect(url_for('profile'))
            current_user.username = new_username

        # 如果修改密码
        if new_password:
            if new_password != confirm_password:
                flash('两次输入的新密码不一致。', 'danger')
                return redirect(url_for('profile'))
            current_user.set_password(new_password)

        db.session.commit()
        flash('账户信息修改成功。', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('profile.html')


# --- 初始化数据库和管理员账户 ---

def init_db_and_admin():
    """初始化数据库表并创建第一个管理员账户"""
    with app.app_context():
        db.create_all()

        # 检查是否已有管理员用户
        if User.query.filter_by(username='admin').first() is None:
            admin_user = User(username='admin')
            # ⚠️ 第一次运行时，请将 'initial_admin_password' 替换为你想要的密码
            admin_user.set_password('123456') 
            db.session.add(admin_user)
            db.session.commit()
            print("--- 重要的管理账户信息 ---")
            print("管理员账户已创建。")
            print("用户名: admin")
            print("密码: 123456 (请务必在登录后修改或删除此函数)")
            print("-------------------------")

if __name__ == '__main__':
    # 第一次运行：初始化数据库和管理员。
    # ⚠️ 生产环境部署时，建议在命令行单独执行一次初始化，然后删除这一行
    # init_db_and_admin() 
    app.run(debug=True)

# 生产环境将使用 Gunicorn 启动

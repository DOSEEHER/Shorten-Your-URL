import hashlib, hmac, ipaddress, os, re, secrets, socket
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
import requests
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {'1', 'true', 'yes', 'on'}


def load_secret(data_dir):
    configured = os.environ.get('SECRET_KEY')
    if configured:
        if len(configured) < 32:
            raise RuntimeError('SECRET_KEY 至少需要 32 个字符')
        return configured
    path = data_dir / '.secret_key'
    if path.exists():
        return path.read_text(encoding='utf-8').strip()
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding='utf-8')
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('DATA_DIR', BASE_DIR / 'instance')).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret(DATA_DIR),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', f"sqlite:///{(DATA_DIR / 'shortener.db').as_posix()}"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'timeout': 30}},
    MAX_CONTENT_LENGTH=1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('COOKIE_SECURE'),
    WTF_CSRF_TIME_LIMIT=3600,
)
trusted_hosts = [host.strip() for host in os.environ.get('TRUSTED_HOSTS', '').split(',') if host.strip()]
if trusted_hosts:
    app.config['TRUSTED_HOSTS'] = trusted_hosts

proxy_count = int(os.environ.get('TRUST_PROXY_COUNT', '0'))
if proxy_count:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_count, x_proto=proxy_count, x_host=proxy_count)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录。'
login_manager.login_message_category = 'info'


@event.listens_for(Engine, 'connect')
def configure_sqlite(connection, _record):
    if connection.__class__.__module__.startswith('sqlite3'):
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA busy_timeout=30000')
        cursor.close()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    auth_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    links = db.relationship('Link', back_populates='owner', cascade='all, delete-orphan')

    @property
    def is_active(self):
        return self.enabled

    def get_id(self):
        return f'{self.id}:{self.auth_version}'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    short_code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    original_url = db.Column(db.String(2048), nullable=False)
    note = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    clicks = db.Column(db.Integer, nullable=False, default=0)
    mode = db.Column(db.String(10), nullable=False, default='redirect')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    owner = db.relationship('User', back_populates='links')


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    ip_hash = db.Column(db.String(64), nullable=False, index=True)
    succeeded = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


@login_manager.user_loader
def load_user(session_id):
    try:
        user_id, version = (int(v) for v in session_id.split(':', 1))
    except (TypeError, ValueError):
        return None
    user = db.session.get(User, user_id)
    return user if user and user.enabled and user.auth_version == version else None


@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response


@app.errorhandler(CSRFError)
def csrf_error(_error):
    flash('页面已过期或请求无效，请重试。', 'danger')
    return redirect(url_for('index'))


def client_ip_hash():
    return hmac.new(app.config['SECRET_KEY'].encode(), (request.remote_addr or 'unknown').encode(), hashlib.sha256).hexdigest()


def ip_blocked(ip_hash):
    cutoff = utcnow() - timedelta(minutes=15)
    return LoginAttempt.query.filter(LoginAttempt.ip_hash == ip_hash, LoginAttempt.succeeded.is_(False), LoginAttempt.created_at >= cutoff).count() >= 20


def record_attempt(ip_hash, succeeded):
    db.session.add(LoginAttempt(ip_hash=ip_hash, succeeded=succeeded))
    LoginAttempt.query.filter(LoginAttempt.created_at < utcnow() - timedelta(days=1)).delete()


COMMON_PASSWORDS = {'123456', '12345678', '123456789', 'password', 'password123', 'qwerty123', 'admin123', 'letmein', 'welcome', 'iloveyou'}
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,64}$')
SHORT_CODE_PATTERN = re.compile(r'^[A-Za-z0-9_-]{3,50}$')


def password_error(password, username=''):
    if len(password or '') < 12:
        return '密码至少需要 12 个字符。'
    if password.lower() in COMMON_PASSWORDS or (username and username.lower() in password.lower()):
        return '密码过于常见或包含用户名，请更换。'
    groups = sum(bool(re.search(p, password)) for p in (r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'))
    return '密码需包含大小写字母、数字、特殊字符中的至少三类。' if groups < 3 else None


def normalized_url(value):
    value = (value or '').strip()
    parsed = urlparse(value)
    return value if parsed.scheme in {'http', 'https'} and parsed.hostname and not parsed.username and not parsed.password else None


def public_proxy_target(url):
    try:
        addresses = socket.getaddrinfo(urlparse(url).hostname, None)
        return all(ipaddress.ip_address(address[4][0]).is_global for address in addresses)
    except (socket.gaierror, ValueError):
        return False


def unique_code(length=7):
    alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    while True:
        code = ''.join(secrets.choice(alphabet) for _ in range(length))
        if not Link.query.filter_by(short_code=code).first():
            return code


def owned_link(short_code):
    return Link.query.filter_by(short_code=short_code, owner_id=current_user.id).first_or_404()


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def settings():
    configured = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/')
    return {'public_base_url': configured or request.url_root.rstrip('/'), 'proxy_enabled': env_bool('ENABLE_PROXY')}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/healthz')
def healthz():
    db.session.execute(db.select(User.id).limit(1))
    return {'status': 'ok'}


@app.route('/<short_code>')
def redirect_to_url(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()
    target = normalized_url(link.original_url)
    if not target:
        abort(410)
    link.clicks = Link.clicks + 1
    db.session.commit()
    if link.mode != 'proxy':
        return redirect(target, 302)
    if not env_bool('ENABLE_PROXY') or not public_proxy_target(target):
        abort(403)
    try:
        response = requests.get(target, timeout=(3.05, 15), allow_redirects=False, stream=True, headers={'User-Agent': 'ShortenYourURL/1.0'})
        content = bytearray()
        for chunk in response.iter_content(64 * 1024):
            content.extend(chunk)
            if len(content) > 10 * 1024 * 1024:
                response.close()
                abort(413)
        headers = {k: v for k, v in response.headers.items() if k.lower() in {'content-type', 'cache-control', 'last-modified', 'etag'}}
        response.close()
        return bytes(content), response.status_code, headers
    except requests.RequestException:
        app.logger.exception('代理目标访问失败')
        abort(502)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    if request.method == 'GET':
        return render_template('login.html')
    ip_hash = client_ip_hash()
    if ip_blocked(ip_hash):
        flash('登录尝试过于频繁，请 15 分钟后再试。', 'danger')
        return render_template('login.html'), 429
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    user = User.query.filter_by(username=username).first()
    valid = user.check_password(password) if user else False
    if not user:
        check_password_hash(app.config['DUMMY_PASSWORD_HASH'], password)
    now = utcnow()
    locked = bool(user and user.locked_until and user.locked_until > now)
    if locked:
        valid = False
    if valid and user.enabled:
        user.failed_login_count, user.locked_until = 0, None
        record_attempt(ip_hash, True)
        db.session.commit()
        login_user(user)
        return redirect(url_for('admin_dashboard'))
    if user and user.enabled and not locked:
        user.failed_login_count += 1
        if user.failed_login_count >= 5:
            user.locked_until = now + timedelta(minutes=15 * (2 ** min(user.failed_login_count - 5, 4)))
    record_attempt(ip_hash, False)
    db.session.commit()
    flash('用户名或密码错误，或账号暂时不可用。', 'danger')
    return render_template('login.html'), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('您已安全退出。', 'info')
    return redirect(url_for('login'))


@app.route('/admin')
@login_required
def admin_dashboard():
    links = Link.query.filter_by(owner_id=current_user.id).order_by(Link.created_at.desc()).all()
    return render_template('admin.html', links=links)


@app.route('/admin/create', methods=['POST'])
@login_required
def create_link():
    target = normalized_url(request.form.get('original_url'))
    code = (request.form.get('custom_code') or '').strip()
    mode = request.form.get('mode', 'redirect')
    if not target:
        flash('请输入有效的 HTTP/HTTPS 链接，且链接中不能包含账号凭证。', 'danger')
    elif code and not SHORT_CODE_PATTERN.fullmatch(code):
        flash('短码需为 3-50 位字母、数字、下划线或短横线。', 'danger')
    elif code and Link.query.filter_by(short_code=code).first():
        flash(f'短码 “{code}” 已被占用。', 'danger')
    else:
        mode = mode if mode in {'redirect', 'proxy'} and (mode != 'proxy' or env_bool('ENABLE_PROXY')) else 'redirect'
        link = Link(original_url=target, short_code=code or unique_code(), note=(request.form.get('note') or '').strip()[:255], mode=mode, owner=current_user)
        db.session.add(link)
        db.session.commit()
        flash(f'短链接创建成功：{link.short_code}', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit/<short_code>', methods=['GET', 'POST'])
@login_required
def edit_link(short_code):
    link = owned_link(short_code)
    if request.method == 'GET':
        return render_template('edit.html', link=link)
    target = normalized_url(request.form.get('original_url'))
    if not target:
        flash('请输入有效的 HTTP/HTTPS 链接。', 'danger')
        return redirect(url_for('edit_link', short_code=short_code))
    mode = request.form.get('mode', 'redirect')
    link.original_url = target
    link.note = (request.form.get('note') or '').strip()[:255]
    link.mode = mode if mode in {'redirect', 'proxy'} and (mode != 'proxy' or env_bool('ENABLE_PROXY')) else 'redirect'
    db.session.commit()
    flash(f'短码 “{short_code}” 已更新。', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/<short_code>', methods=['POST'])
@login_required
def delete_link(short_code):
    db.session.delete(owned_link(short_code))
    db.session.commit()
    flash(f'短码 “{short_code}” 已删除。', 'info')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        return render_template('profile.html')
    current_password = request.form.get('current_password') or ''
    username = (request.form.get('new_username') or '').strip()
    password = request.form.get('new_password') or ''
    error = password_error(password, username) if password else None
    if not current_user.check_password(current_password):
        flash('当前密码错误。', 'danger')
    elif not USERNAME_PATTERN.fullmatch(username):
        flash('用户名需为 3-64 位字母、数字、点、下划线或短横线。', 'danger')
    elif User.query.filter(User.username == username, User.id != current_user.id).first():
        flash('用户名已存在。', 'danger')
    elif password and password != (request.form.get('confirm_password') or ''):
        flash('两次输入的新密码不一致。', 'danger')
    elif error:
        flash(error, 'danger')
    else:
        current_user.username = username
        if password:
            current_user.set_password(password)
            current_user.auth_version += 1
        db.session.commit()
        if password:
            login_user(current_user)
        flash('账户信息已更新。', 'success')
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('profile'))


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        error = password_error(password, username)
        if not USERNAME_PATTERN.fullmatch(username):
            flash('用户名格式无效。', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('用户名已存在。', 'danger')
        elif error:
            flash(error, 'danger')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f'账号 “{username}” 已创建。', 'success')
            return redirect(url_for('manage_users'))
    return render_template('users.html', users=User.query.order_by(User.created_at).all())


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id or user.is_admin:
        abort(400)
    user.enabled = not user.enabled
    user.auth_version += 1
    db.session.commit()
    flash(f'账号 “{user.username}” 已{"启用" if user.enabled else "停用"}。', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin/users/<int:user_id>/password', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    user = db.get_or_404(User, user_id)
    password = request.form.get('password') or ''
    error = password_error(password, user.username)
    if error:
        flash(error, 'danger')
    else:
        user.set_password(password)
        user.auth_version += 1
        user.failed_login_count, user.locked_until = 0, None
        db.session.commit()
        flash(f'账号 “{user.username}” 的密码已重置，原会话已失效。', 'success')
    return redirect(url_for('manage_users'))


def init_db_and_admin():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            username = os.environ.get('ADMIN_USERNAME', 'admin').strip()
            password = os.environ.get('ADMIN_PASSWORD', '')
            error = password_error(password, username)
            if not USERNAME_PATTERN.fullmatch(username):
                raise RuntimeError('ADMIN_USERNAME 格式无效')
            if error:
                raise RuntimeError(f'首次启动需要安全的 ADMIN_PASSWORD：{error}')
            admin = User(username=username, is_admin=True)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            app.logger.warning('初始管理员 %s 已创建，请妥善保管密码。', username)


app.config['DUMMY_PASSWORD_HASH'] = generate_password_hash(secrets.token_urlsafe(32), method='scrypt')

if __name__ == '__main__':
    init_db_and_admin()
    app.run(host='0.0.0.0', port=5000, debug=env_bool('FLASK_DEBUG'))

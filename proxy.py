import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import socket
import threading
import time
from http.cookiejar import DefaultCookiePolicy
from http.cookies import CookieError, SimpleCookie
from urllib.parse import quote, urljoin, urlparse

import requests
from flask import Response, abort, request, stream_with_context
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, HTTPError as Urllib3HTTPError, NewConnectionError
from urllib3.util import connection as urllib3_connection
from urllib3.util.retry import Retry
from werkzeug.datastructures import Headers

PROXY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
PROXY_COOKIE_NAME = '__syu_proxy'
UPSTREAM_COOKIE_PREFIX = '__syu_uc_'
PROXY_CSP = (
    "default-src 'self' blob: data: https: http:; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob: data: https: http:; "
    "style-src 'self' 'unsafe-inline' blob: data: https: http:; "
    "img-src 'self' blob: data: https: http:; "
    "font-src 'self' blob: data: https: http:; "
    "connect-src 'self' blob: data: https: http: wss: ws:; "
    "media-src 'self' blob: data: https: http:; "
    "worker-src 'self' blob: data:; "
    "child-src 'self' blob: data:; "
    "frame-ancestors 'self'"
)

PASSTHROUGH_RESPONSE_HEADERS = {
    'content-type',
    'content-disposition',
    'cache-control',
    'last-modified',
    'etag',
    'expires',
    'accept-ranges',
    'content-range',
    'vary',
    'access-control-expose-headers',
}

FORWARDED_REQUEST_HEADERS = {
    'accept',
    'accept-language',
    'cache-control',
    'content-type',
    'if-modified-since',
    'if-none-match',
    'pragma',
    'range',
    'rsc',
    'next-router-prefetch',
    'next-router-segment-prefetch',
    'next-router-state-tree',
    'next-url',
    'x-deployment-id',
    'x-device-id',
    'x-requested-with',
}

INTERNAL_PROTECTED_PREFIXES = ('/login', '/logout', '/admin', '/healthz', '/register')

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/131.0.0.0 Safari/537.36'
)

NON_HTTP_SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.-]*):')
CHARSET_RE = re.compile(r'charset=([^\s;]+)', re.IGNORECASE)
META_CHARSET_RE = re.compile(rb'<meta[^>]+charset=["\']?\s*([a-zA-Z0-9._-]+)', re.IGNORECASE)
META_REFRESH_RE = re.compile(r'^(\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*)(["\']?)(.*?)\2\s*$', re.IGNORECASE)

_TAG_ATTRS_PAT = r'(?:[^>"\']|"[^"]*"|\'[^\']*\')*'
HTML_TOKEN_RE = re.compile(
    r'(?is)'
    r'(<!--.*?-->)'
    rf'|(<script\b{_TAG_ATTRS_PAT}>)(.*?)(</script\s*>)'
    rf'|(<style\b{_TAG_ATTRS_PAT}>)(.*?)(</style\s*>)'
    rf'|(<[a-zA-Z][a-zA-Z0-9:-]*{_TAG_ATTRS_PAT}>)'
)
TAG_NAME_RE = re.compile(r'^<\s*([a-zA-Z0-9:-]+)')
ATTR_RE = re.compile(
    r"""(\b(?:href|xlink:href|src|data|poster|action|srcset|integrity|rel|as|style|http-equiv|content)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""",
    re.IGNORECASE,
)
CSS_URL_RE = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']+))\s*\)""", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r"""(@import\s+)(?:"([^"]+)"|'([^']+)')""", re.IGNORECASE)
SAFE_COOKIE_NAME_RE = re.compile(r'^[A-Za-z0-9!#$%&\'*+\-.^_`|~]{1,64}$')


class UnsafeProxyTargetError(Exception):
    """Raised when an upstream hostname resolves to a non-public or disallowed IP address."""


class _RejectAllCookiesPolicy(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


_pin_dns_tls = threading.local()
_session_lock = threading.Lock()
_shared_session = None

_origin_cache_lock = threading.Lock()
_resolved_origin_cache = {}
ORIGIN_CACHE_TTL = 600.0

_sse_lock = threading.Lock()
_sse_semaphore = None
_sse_semaphore_limit = 0


def _env_flag(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {'1', 'true', 'yes', 'on'}


def _is_public_ip_address(raw_ip):
    ip_obj = ipaddress.ip_address(raw_ip)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_global
        and not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


def resolve_public_ip_targets(hostname, port=None):
    if not hostname:
        raise UnsafeProxyTargetError('Missing upstream hostname')
    clean_host = hostname.strip('[]')
    try:
        literal_ip = ipaddress.ip_address(clean_host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not _is_public_ip_address(clean_host):
            raise UnsafeProxyTargetError(f'Disallowed non-public literal IP: {clean_host}')
        return [clean_host]

    try:
        infos = socket.getaddrinfo(clean_host, port or 80, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, ValueError, OSError) as exc:
        raise UnsafeProxyTargetError(f'DNS resolution failed for {clean_host}') from exc

    if not infos:
        raise UnsafeProxyTargetError(f'No DNS records returned for {clean_host}')

    validated_ips = []
    seen = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        try:
            ok = _is_public_ip_address(ip_str)
        except ValueError:
            ok = False
        if not ok:
            raise UnsafeProxyTargetError(f'Host {clean_host} resolved to non-public IP {ip_str}')
        if ip_str not in seen:
            seen.add(ip_str)
            validated_ips.append(ip_str)

    if not validated_ips:
        raise UnsafeProxyTargetError(f'No valid public IP for {clean_host}')
    return validated_ips


class _SafeHTTPConnectionMixin:
    def _new_conn(self):
        if not getattr(_pin_dns_tls, 'enforce_public_ip', True):
            return super()._new_conn()

        validated_ips = resolve_public_ip_targets(self._dns_host, self.port)
        last_err = None
        for ip_str in validated_ips:
            try:
                return urllib3_connection.create_connection(
                    (ip_str, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.timeout as exc:
                raise ConnectTimeoutError(
                    self,
                    f'Connection to {self.host} timed out. (connect timeout={self.timeout})',
                ) from exc
            except OSError as exc:
                last_err = exc
                continue
        raise NewConnectionError(self, f'Failed to establish a new connection: {last_err}')


class _SafeHTTPConnection(_SafeHTTPConnectionMixin, HTTPConnection):
    pass


class _SafeHTTPSConnection(_SafeHTTPConnectionMixin, HTTPSConnection):
    pass


class _SafeHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _SafeHTTPConnection


class _SafeHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _SafeHTTPSConnection


class _SafePublicIPHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            'http': _SafeHTTPConnectionPool,
            'https': _SafeHTTPSConnectionPool,
        }


def get_proxy_session():
    global _shared_session
    if _shared_session is None:
        with _session_lock:
            if _shared_session is None:
                session = requests.Session()
                session.cookies.set_policy(_RejectAllCookiesPolicy())
                retry_strategy = Retry(
                    total=2,
                    connect=2,
                    read=1,
                    redirect=False,
                    status=0,
                    allowed_methods=frozenset({'GET', 'HEAD', 'OPTIONS'}),
                    backoff_factor=0.2,
                )
                adapter = _SafePublicIPHTTPAdapter(
                    pool_connections=16,
                    pool_maxsize=32,
                    max_retries=retry_strategy,
                )
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                _shared_session = session
    return _shared_session


def clear_dns_cache():
    with _origin_cache_lock:
        _resolved_origin_cache.clear()


def is_public_proxy_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    if not _env_flag('PROXY_ALLOW_CUSTOM_PORTS', False) and port not in {None, 80, 443}:
        return False
    try:
        resolve_public_ip_targets(parsed.hostname, port)
        return True
    except UnsafeProxyTargetError:
        return False


def is_allowed_external_netloc(scheme, netloc):
    if not netloc or '/' in netloc or '\\' in netloc or '@' in netloc or any(c.isspace() for c in netloc):
        return False
    parsed = urlparse(f'{scheme}://{netloc}')
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        return False
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    if not _env_flag('PROXY_ALLOW_CUSTOM_PORTS', False) and port not in {None, 80, 443}:
        return False
    return True


def is_blocked_worker_request(req=None):
    req = req or request
    if req.headers.get('Service-Worker'):
        return True
    sec_dest = (req.headers.get('Sec-Fetch-Dest') or '').strip().lower()
    return sec_dest in {'serviceworker', 'sharedworker'}


def proxy_max_bytes():
    try:
        mb = int(os.environ.get('PROXY_MAX_MB', '50'))
    except ValueError:
        mb = 50
    return max(1, mb) * 1024 * 1024


def proxy_max_request_bytes():
    try:
        default_mb = min(50, max(1, int(os.environ.get('PROXY_MAX_MB', '50'))))
    except ValueError:
        default_mb = 20
    try:
        req_mb = int(os.environ.get('PROXY_MAX_REQUEST_MB', str(min(default_mb, 20))))
    except ValueError:
        req_mb = 20
    return max(1, req_mb) * 1024 * 1024


def proxy_rewrite_max_bytes():
    try:
        rw_mb = int(os.environ.get('PROXY_REWRITE_MAX_MB', '25'))
    except ValueError:
        rw_mb = 25
    return min(proxy_max_bytes(), max(1, rw_mb) * 1024 * 1024)


def proxy_session_ttl():
    try:
        return max(60, int(os.environ.get('PROXY_SESSION_TTL', '21600')))
    except ValueError:
        return 21600


def _get_sse_semaphore():
    global _sse_semaphore, _sse_semaphore_limit
    try:
        limit = max(2, int(os.environ.get('PROXY_MAX_SSE_STREAMS', '6')))
    except ValueError:
        limit = 6
    with _sse_lock:
        if _sse_semaphore is None or _sse_semaphore_limit != limit:
            _sse_semaphore = threading.BoundedSemaphore(limit)
            _sse_semaphore_limit = limit
        return _sse_semaphore


def _sign_cookie_payload(secret_key, payload):
    return hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()[:32]


def _normalize_origin(origin_str):
    if not origin_str or not isinstance(origin_str, str):
        return ''
    parsed = urlparse(origin_str)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc or parsed.username or parsed.password:
        return ''
    if parsed.path or parsed.query or parsed.fragment:
        return ''
    return f'{parsed.scheme}://{parsed.netloc}'


def _parse_proxy_cookie_entries(secret_key, raw_cookie):
    if not secret_key or not raw_cookie or '.' not in raw_cookie:
        return []
    parts = raw_cookie.split('.')
    if len(parts) != 3:
        return []
    payload_part, ts_str, sig = parts
    expected = _sign_cookie_payload(secret_key, f'{payload_part}.{ts_str}')
    if not hmac.compare_digest(sig, expected):
        return []
    try:
        issued = int(ts_str)
    except ValueError:
        return []
    if issued + proxy_session_ttl() < int(time.time()):
        return []

    if payload_part.startswith('v2_'):
        b64 = payload_part[3:]
        pad = '=' * (-len(b64) % 4)
        try:
            decoded = base64.urlsafe_b64decode((b64 + pad).encode('ascii')).decode('utf-8')
            items = json.loads(decoded)
        except Exception:
            return []
        if not isinstance(items, list):
            return []
        entries = []
        for item in items:
            if isinstance(item, list) and len(item) == 2 and isinstance(item[0], str) and item[0]:
                entries.append((item[0], _normalize_origin(item[1])))
        return entries

    return [(c, '') for c in payload_part.split(':') if c]


def parse_proxy_cookie(secret_key, raw_cookie):
    return [code for code, _ in _parse_proxy_cookie_entries(secret_key, raw_cookie)]


def parse_proxy_cookie_origins(secret_key, raw_cookie):
    return {code: origin for code, origin in _parse_proxy_cookie_entries(secret_key, raw_cookie) if origin}


def build_proxy_cookie(secret_key, existing_cookie, short_code, resolved_origin=''):
    norm_origin = _normalize_origin(resolved_origin)
    prev = _parse_proxy_cookie_entries(secret_key, existing_cookie)
    entries = [(c, o) for c, o in prev if c != short_code]
    if not norm_origin:
        for c, o in prev:
            if c == short_code and o:
                norm_origin = o
                break
    entries.append((short_code, norm_origin))
    entries = entries[-10:]
    raw_json = json.dumps([[c, o] for c, o in entries], separators=(',', ':')).encode('utf-8')
    b64 = base64.urlsafe_b64encode(raw_json).decode('ascii').rstrip('=')
    payload_part = f'v2_{b64}'
    ts_str = str(int(time.time()))
    sig = _sign_cookie_payload(secret_key, f'{payload_part}.{ts_str}')
    return f'{payload_part}.{ts_str}.{sig}'


def remember_resolved_origin(short_code, entry_origin, final_origin):
    norm_entry = _normalize_origin(entry_origin)
    norm_final = _normalize_origin(final_origin)
    if not short_code or not norm_entry or not norm_final:
        return
    now = time.monotonic()
    with _origin_cache_lock:
        if len(_resolved_origin_cache) > 1024:
            _resolved_origin_cache.clear()
        _resolved_origin_cache[(short_code, norm_entry)] = (norm_final, now + ORIGIN_CACHE_TTL)


def get_effective_target_origin(secret_key, short_code, entry_origin, req=None):
    req = req or request
    norm_entry = _normalize_origin(entry_origin) or entry_origin
    if secret_key:
        cookie_origins = parse_proxy_cookie_origins(secret_key, req.cookies.get(PROXY_COOKIE_NAME))
        from_cookie = cookie_origins.get(short_code)
        if from_cookie:
            return from_cookie
    now = time.monotonic()
    with _origin_cache_lock:
        cached = _resolved_origin_cache.get((short_code, norm_entry))
        if cached and cached[1] > now:
            return cached[0]
    return norm_entry


def extract_referer_short_code(short_code_pattern):
    referer = request.headers.get('Referer')
    if not referer:
        return None
    parsed = urlparse(referer)
    if parsed.netloc and parsed.netloc != request.host:
        return None
    path = parsed.path or ''
    if path.startswith('/_p/'):
        rest = path[4:]
        code = rest.split('/', 1)[0]
        return code if short_code_pattern.fullmatch(code) else None
    if path.startswith('/') and path.count('/') == 1:
        code = path[1:]
        return code if short_code_pattern.fullmatch(code) else None
    return None


def has_valid_proxy_context(secret_key, short_code, short_code_pattern=None):
    """Require cryptographic HMAC-signed proxy session cookie; never trust bare Referer headers."""
    if not secret_key or not short_code:
        return False
    codes = parse_proxy_cookie(secret_key, request.cookies.get(PROXY_COOKIE_NAME))
    if short_code not in codes:
        return False
    if short_code_pattern is not None and request.headers.get('Referer'):
        ref_code = extract_referer_short_code(short_code_pattern)
        if ref_code and ref_code != short_code and ref_code in codes:
            return False
    return True


def to_proxy_url(raw_url, base_url, target_origin, short_code, same_origin_only=False):
    if raw_url is None:
        return raw_url
    value = raw_url.strip()
    if not value or value.startswith('#'):
        return raw_url
    p_prefix = f'/_p/{short_code}'
    px_prefix = f'/_px/{short_code}'
    if (
        value == p_prefix
        or value.startswith(f'{p_prefix}/')
        or value.startswith(f'{p_prefix}?')
        or value.startswith(f'{px_prefix}/')
    ):
        return raw_url

    scheme_match = NON_HTTP_SCHEME_RE.match(value)
    if scheme_match and scheme_match.group(1).lower() not in {'http', 'https'}:
        return raw_url

    resolved = urljoin(base_url, value)
    parsed = urlparse(resolved)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc or parsed.username or parsed.password:
        return raw_url

    resolved_origin = f'{parsed.scheme}://{parsed.netloc}'
    path = parsed.path or '/'
    suffix = path
    if parsed.query:
        suffix = f'{suffix}?{parsed.query}'
    if parsed.fragment:
        suffix = f'{suffix}#{parsed.fragment}'

    if resolved_origin == target_origin:
        return f'{p_prefix}{suffix}'
    if same_origin_only:
        return raw_url
    if not is_allowed_external_netloc(parsed.scheme, parsed.netloc):
        return raw_url
    return f'{px_prefix}/{parsed.scheme}/{parsed.netloc}{suffix}'


def rewrite_srcset(srcset_value, base_url, target_origin, short_code):
    parts = re.split(r',\s+(?=\S)', srcset_value.strip())
    rewritten = []
    for item in parts:
        tokens = item.strip().split(None, 1)
        if not tokens:
            continue
        url_part = to_proxy_url(tokens[0], base_url, target_origin, short_code)
        rewritten.append(f'{url_part} {tokens[1]}' if len(tokens) > 1 else url_part)
    return ', '.join(rewritten)


def rewrite_css_for_proxy(css_text, base_url, target_origin, short_code):
    def replace_import(match):
        prefix = match.group(1)
        raw_ref = match.group(2) if match.group(2) is not None else match.group(3)
        quote_char = '"' if match.group(2) is not None else "'"
        proxied = to_proxy_url(raw_ref, base_url, target_origin, short_code)
        return f'{prefix}{quote_char}{proxied}{quote_char}'

    def replace_url(match):
        if match.group(1) is not None:
            raw_ref, quote_char = match.group(1), '"'
        elif match.group(2) is not None:
            raw_ref, quote_char = match.group(2), "'"
        else:
            raw_ref, quote_char = match.group(3), ''
        stripped = raw_ref.strip()
        if not stripped or stripped.startswith(('#', 'data:', 'blob:')):
            return match.group(0)
        proxied = to_proxy_url(stripped, base_url, target_origin, short_code)
        return f'url({quote_char}{proxied}{quote_char})'

    css_text = CSS_IMPORT_RE.sub(replace_import, css_text)
    return CSS_URL_RE.sub(replace_url, css_text)


def build_proxy_shim_script(short_code, current_upstream_url, target_origin, canonical_entry_url=''):
    parsed_canonical = urlparse(canonical_entry_url or current_upstream_url)
    entry_path = parsed_canonical.path or '/'
    config_json = json.dumps(
        {
            'code': short_code,
            'entryUrl': current_upstream_url,
            'entryPath': entry_path,
            'targetOrigin': target_origin,
            'pPrefix': f'/_p/{short_code}',
            'pxPrefix': f'/_px/{short_code}',
            'shortPath': f'/{short_code}',
        },
        ensure_ascii=False,
    ).replace('</', '<\\/')

    return (
        f'<script data-syu-proxy="1">(function(){{"use strict";'
        f'const CFG={config_json};'
        r"""
let currentUpstreamUrl = CFG.entryUrl;
const NON_HTTP_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):/;
const PROTECTED_RE = /^\/(?:login|logout|admin|healthz|register)(?:\/|$)/i;

function isAlreadyProxiedPath(pathname) {
  return (
    pathname === CFG.shortPath ||
    pathname === CFG.pPrefix ||
    pathname.startsWith(CFG.pPrefix + '/') ||
    pathname.startsWith(CFG.pxPrefix + '/')
  );
}

function rewriteUrl(raw, sameOriginOnly) {
  if (raw == null) return raw;
  const str = String(raw).trim();
  if (!str || str[0] === '#') return raw;
  if (
    str === CFG.pPrefix ||
    str.startsWith(CFG.pPrefix + '/') ||
    str.startsWith(CFG.pPrefix + '?') ||
    str.startsWith(CFG.pxPrefix + '/')
  ) {
    return String(raw);
  }
  const m = NON_HTTP_RE.exec(str);
  if (m) {
    const scheme = m[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') return raw;
  }
  let u;
  try {
    u = new URL(str, currentUpstreamUrl);
  } catch {
    return raw;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return raw;
  const path = u.pathname || '/';
  const suffix = path + u.search + u.hash;
  if (u.origin === CFG.targetOrigin) {
    return CFG.pPrefix + suffix;
  }
  if (u.origin === location.origin) {
    if (isAlreadyProxiedPath(path)) return String(raw);
    if (PROTECTED_RE.test(path)) return 'about:blank';
    return CFG.pPrefix + suffix;
  }
  if (sameOriginOnly) return raw;
  if (u.port && u.port !== '80' && u.port !== '443') return raw;
  return CFG.pxPrefix + '/' + u.protocol.slice(0, -1) + '/' + u.host + suffix;
}

function rewriteSrcset(val) {
  if (typeof val !== 'string' || !val.trim()) return val;
  return val
    .trim()
    .split(/,\s+(?=\S)/)
    .map(function (part) {
      const idx = part.search(/\s/);
      if (idx === -1) return rewriteUrl(part, false);
      return rewriteUrl(part.slice(0, idx), false) + part.slice(idx);
    })
    .join(', ');
}

function rewriteCssUrls(text) {
  if (typeof text !== 'string' || text.indexOf('url(') === -1) return text;
  return text.replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']+))\s*\)/gi, function (all, dq, sq, bare) {
    const ref = dq != null ? dq : sq != null ? sq : bare;
    const q = dq != null ? '"' : sq != null ? "'" : '';
    if (!ref || ref[0] === '#' || ref.startsWith('data:') || ref.startsWith('blob:')) return all;
    return 'url(' + q + rewriteUrl(ref, false) + q + ')';
  });
}

function rewriteHistoryUrl(url) {
  if (url == null || url === '') return url;
  const str = String(url);
  let u;
  try {
    u = new URL(str, currentUpstreamUrl);
  } catch {
    return url;
  }
  if (u.origin === location.origin) {
    if (PROTECTED_RE.test(u.pathname)) return CFG.shortPath;
    if (u.pathname === CFG.shortPath) {
      currentUpstreamUrl = CFG.targetOrigin + CFG.entryPath + u.search + u.hash;
      return CFG.shortPath + u.search + u.hash;
    }
    if (u.pathname === CFG.pPrefix || u.pathname.startsWith(CFG.pPrefix + '/')) {
      const sub = u.pathname.slice(CFG.pPrefix.length) || '/';
      currentUpstreamUrl = CFG.targetOrigin + sub + u.search + u.hash;
      return sub === CFG.entryPath ? CFG.shortPath + u.search + u.hash : u.pathname + u.search + u.hash;
    }
    currentUpstreamUrl = CFG.targetOrigin + u.pathname + u.search + u.hash;
    return u.pathname === CFG.entryPath
      ? CFG.shortPath + u.search + u.hash
      : CFG.pPrefix + u.pathname + u.search + u.hash;
  }
  if (u.origin === CFG.targetOrigin) {
    currentUpstreamUrl = u.href;
    return u.pathname === CFG.entryPath
      ? CFG.shortPath + u.search + u.hash
      : CFG.pPrefix + (u.pathname || '/') + u.search + u.hash;
  }
  return url;
}

if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
  navigator.serviceWorker.register = function () {
    return Promise.reject(new DOMException('ServiceWorker registration is disabled in proxy mode.', 'SecurityError'));
  };
}

if (typeof window.open === 'function') {
  const origWindowOpen = window.open;
  window.open = function (url, target, features) {
    if (url != null && String(url).trim() !== '') {
      try {
        const parsed = new URL(String(url), currentUpstreamUrl);
        if (parsed.origin === location.origin && PROTECTED_RE.test(parsed.pathname)) {
          return null;
        }
      } catch {}
      url = rewriteUrl(url, true);
    }
    const safeFeatures = features ? String(features) + ',noopener' : 'noopener';
    return origWindowOpen.call(this, url, target, safeFeatures);
  };
}

if (typeof window.trustedTypes !== 'undefined' && window.trustedTypes && window.trustedTypes.createPolicy) {
  const origCreatePolicy = window.trustedTypes.createPolicy.bind(window.trustedTypes);
  window.trustedTypes.createPolicy = function (name, rules) {
    if (rules && typeof rules === 'object') {
      const wrapped = Object.assign({}, rules);
      if (typeof rules.createScriptURL === 'function') {
        const fn = rules.createScriptURL;
        wrapped.createScriptURL = function () {
          const out = fn.apply(this, arguments);
          return rewriteUrl(out, false);
        };
      }
      if (typeof rules.createURL === 'function') {
        const fn = rules.createURL;
        wrapped.createURL = function () {
          const out = fn.apply(this, arguments);
          return rewriteUrl(out, false);
        };
      }
      return origCreatePolicy(name, wrapped);
    }
    return origCreatePolicy(name, rules);
  };
}

if (typeof window.fetch === 'function') {
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    if (typeof Request !== 'undefined' && input instanceof Request) {
      const nextUrl = rewriteUrl(input.url, false);
      if (nextUrl !== input.url) {
        input = new Request(nextUrl, input);
      }
      return origFetch.call(this, input, init);
    }
    return origFetch.call(this, rewriteUrl(input, false), init);
  };
}

if (typeof XMLHttpRequest !== 'undefined') {
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    const args = Array.prototype.slice.call(arguments);
    args[1] = rewriteUrl(url, false);
    return origOpen.apply(this, args);
  };
}

if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
  const origBeacon = navigator.sendBeacon;
  navigator.sendBeacon = function (url, data) {
    return origBeacon.call(this, rewriteUrl(url, false), data);
  };
}

if (typeof window.EventSource === 'function') {
  const OrigES = window.EventSource;
  window.EventSource = function (url, conf) {
    return new OrigES(rewriteUrl(url, false), conf);
  };
  window.EventSource.prototype = OrigES.prototype;
}

if (typeof window.Worker === 'function') {
  const OrigWorker = window.Worker;
  window.Worker = function (url, opts) {
    const isTrusted = typeof TrustedScriptURL !== 'undefined' && url instanceof TrustedScriptURL;
    const proxied = isTrusted ? url : rewriteUrl(url, false);
    if (!isTrusted && (!opts || opts.type !== 'module') && typeof Blob !== 'undefined' && typeof URL !== 'undefined' && URL.createObjectURL) {
      try {
        const absWorkerUrl = new URL(String(proxied), location.origin).href;
        const workerBoot =
          '(function(){const ORIGIN=' + JSON.stringify(location.origin) + ',CFG=' + JSON.stringify(CFG) + ';' +
          'function rw(raw){if(raw==null)return raw;const s=String(raw).trim();if(!s||s[0]==="#")return raw;' +
          'if(s===CFG.pPrefix||s.startsWith(CFG.pPrefix+"/")||s.startsWith(CFG.pxPrefix+"/"))return ORIGIN+s;' +
          'let u;try{u=new URL(s,CFG.entryUrl);}catch{return raw;}' +
          'if(u.protocol!=="http:"&&u.protocol!=="https:")return raw;' +
          'const suf=(u.pathname||"/")+u.search+u.hash;' +
          'if(u.origin===CFG.targetOrigin)return ORIGIN+CFG.pPrefix+suf;' +
          'if(u.origin===ORIGIN)return raw;' +
          'return ORIGIN+CFG.pxPrefix+"/"+u.protocol.slice(0,-1)+"/"+u.host+suf;}' +
          'if(typeof self.fetch==="function"){const f=self.fetch;self.fetch=function(i,n){return f.call(this,typeof i==="string"?rw(i):i,n);};}' +
          'if(typeof self.XMLHttpRequest!=="undefined"){const o=self.XMLHttpRequest.prototype.open;self.XMLHttpRequest.prototype.open=function(m,u){const a=[].slice.call(arguments);a[1]=rw(u);return o.apply(this,a);};}' +
          'if(typeof self.importScripts==="function"){const im=self.importScripts;self.importScripts=function(){const a=[].map.call(arguments,rw);return im.apply(this,a);};}' +
          'importScripts(' + JSON.stringify(absWorkerUrl) + ');})();';
        const blobUrl = URL.createObjectURL(new Blob([workerBoot], { type: 'application/javascript' }));
        return new OrigWorker(blobUrl, opts);
      } catch {}
    }
    return new OrigWorker(proxied, opts);
  };
  window.Worker.prototype = OrigWorker.prototype;
}

if (typeof window.FontFace === 'function') {
  const OrigFontFace = window.FontFace;
  window.FontFace = function (family, source, descriptors) {
    return new OrigFontFace(family, typeof source === 'string' ? rewriteCssUrls(source) : source, descriptors);
  };
  window.FontFace.prototype = OrigFontFace.prototype;
}

if (typeof History !== 'undefined') {
  const origPush = History.prototype.pushState;
  const origReplace = History.prototype.replaceState;
  History.prototype.pushState = function (state, title, url) {
    return origPush.call(this, state, title, rewriteHistoryUrl(url));
  };
  History.prototype.replaceState = function (state, title, url) {
    return origReplace.call(this, state, title, rewriteHistoryUrl(url));
  };
}

const SKIP_LINK_RELS = { canonical: 1, alternate: 1, preconnect: 1, 'dns-prefetch': 1 };

function shouldSkipLinkElement(el) {
  const rel = (el.getAttribute && el.getAttribute('rel')) || '';
  if (!rel) return false;
  const tokens = rel.toLowerCase().trim().split(/\s+/);
  return tokens.length > 0 && tokens.every(function (t) { return !!SKIP_LINK_RELS[t]; });
}

if (typeof Element !== 'undefined' && Element.prototype.setAttribute) {
  const origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const attr = String(name).toLowerCase();
    const tag = (this.tagName || '').toLowerCase();
    const isTrusted = typeof TrustedScriptURL !== 'undefined' && value instanceof TrustedScriptURL;
    if (!isTrusted) {
      if (attr === 'src' || attr === 'poster') {
        value = rewriteUrl(value, tag === 'iframe');
      } else if (attr === 'data' && tag === 'object') {
        value = rewriteUrl(value, false);
      } else if (attr === 'href' || attr === 'xlink:href') {
        if (tag === 'link' && !shouldSkipLinkElement(this)) {
          value = rewriteUrl(value, false);
        } else if (tag === 'a' || tag === 'area') {
          value = rewriteUrl(value, true);
        } else if (tag === 'image' || tag === 'use') {
          value = rewriteUrl(value, false);
        }
      } else if (attr === 'srcset') {
        value = rewriteSrcset(String(value));
      } else if (attr === 'action' && tag === 'form') {
        value = rewriteUrl(value, true);
      } else if (attr === 'style') {
        value = rewriteCssUrls(String(value));
      }
    }
    return origSetAttr.call(this, name, value);
  };
}

if (typeof CSSStyleDeclaration !== 'undefined' && CSSStyleDeclaration.prototype.setProperty) {
  const origSetProp = CSSStyleDeclaration.prototype.setProperty;
  CSSStyleDeclaration.prototype.setProperty = function (prop, value, priority) {
    if (typeof value === 'string' && value.indexOf('url(') !== -1) {
      value = rewriteCssUrls(value);
    }
    return origSetProp.call(this, prop, value, priority);
  };
}

function wrapUrlProp(proto, prop, sameOriginOnly, checkFn) {
  if (!proto) return;
  const desc = Object.getOwnPropertyDescriptor(proto, prop);
  if (!desc || !desc.set || !desc.configurable) return;
  Object.defineProperty(proto, prop, {
    configurable: true,
    enumerable: desc.enumerable,
    get: desc.get,
    set: function (val) {
      const isTrusted = typeof TrustedScriptURL !== 'undefined' && val instanceof TrustedScriptURL;
      if (!isTrusted && (!checkFn || checkFn(this))) {
        val = prop === 'srcset' ? rewriteSrcset(String(val)) : rewriteUrl(val, sameOriginOnly);
      }
      return desc.set.call(this, val);
    },
  });
}

wrapUrlProp(typeof HTMLScriptElement !== 'undefined' && HTMLScriptElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLLinkElement !== 'undefined' && HTMLLinkElement.prototype, 'href', false, function (el) {
  return !shouldSkipLinkElement(el);
});
wrapUrlProp(typeof HTMLImageElement !== 'undefined' && HTMLImageElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLImageElement !== 'undefined' && HTMLImageElement.prototype, 'srcset', false);
wrapUrlProp(typeof HTMLSourceElement !== 'undefined' && HTMLSourceElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLSourceElement !== 'undefined' && HTMLSourceElement.prototype, 'srcset', false);
wrapUrlProp(typeof HTMLMediaElement !== 'undefined' && HTMLMediaElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLVideoElement !== 'undefined' && HTMLVideoElement.prototype, 'poster', false);
wrapUrlProp(typeof HTMLAnchorElement !== 'undefined' && HTMLAnchorElement.prototype, 'href', true);
wrapUrlProp(typeof HTMLAreaElement !== 'undefined' && HTMLAreaElement.prototype, 'href', true);
wrapUrlProp(typeof HTMLFormElement !== 'undefined' && HTMLFormElement.prototype, 'action', true);
wrapUrlProp(typeof HTMLIFrameElement !== 'undefined' && HTMLIFrameElement.prototype, 'src', true);
wrapUrlProp(typeof HTMLEmbedElement !== 'undefined' && HTMLEmbedElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLTrackElement !== 'undefined' && HTMLTrackElement.prototype, 'src', false);
wrapUrlProp(typeof HTMLObjectElement !== 'undefined' && HTMLObjectElement.prototype, 'data', false);

if (document.currentScript && document.currentScript.parentNode) {
  document.currentScript.parentNode.removeChild(document.currentScript);
}
"""
        '})();</script>'
    )


def _extract_attr_map(tag_text):
    attrs = {}
    for match in ATTR_RE.finditer(tag_text):
        key = match.group(1).split('=', 1)[0].strip().lower()
        val = (
            match.group(2)
            if match.group(2) is not None
            else (match.group(3) if match.group(3) is not None else match.group(4))
        )
        attrs[key] = html.unescape(val or '')
    return attrs


def _rewrite_open_tag(tag_text, base_url, target_origin, short_code):
    name_match = TAG_NAME_RE.match(tag_text)
    if not name_match:
        return tag_text, base_url, ''
    tag_name = name_match.group(1).lower()
    if tag_text.lstrip().startswith('</'):
        return tag_text, base_url, ''
    attrs = _extract_attr_map(tag_text)

    if tag_name == 'base':
        href = attrs.get('href', '').strip()
        next_base = urljoin(base_url, href) if href else base_url
        return '', next_base, 'base'

    rel_tokens = set(attrs.get('rel', '').lower().split())
    as_val = attrs.get('as', '').lower().strip()
    if tag_name == 'link' and rel_tokens:
        if rel_tokens <= {'preconnect', 'dns-prefetch'}:
            href = attrs.get('href', '').strip()
            if href and urlparse(urljoin(base_url, href)).netloc != urlparse(target_origin).netloc:
                return '', base_url, tag_name
            return tag_text, base_url, tag_name
        if rel_tokens <= {'canonical', 'alternate'}:
            return tag_text, base_url, tag_name

    drop_integrity = tag_name == 'link' and (
        bool(rel_tokens & {'stylesheet', 'preload', 'modulepreload'}) or as_val == 'style'
    )
    is_meta_refresh = tag_name == 'meta' and attrs.get('http-equiv', '').strip().lower() == 'refresh'
    same_origin_only = tag_name in {'a', 'area', 'form', 'iframe'}

    url_bearing_tags = {
        'link', 'img', 'source', 'video', 'audio', 'iframe', 'embed',
        'track', 'form', 'a', 'area', 'script', 'object', 'image', 'use',
    }
    has_style = 'style' in attrs
    if tag_name not in url_bearing_tags and not has_style and not is_meta_refresh:
        return tag_text, base_url, tag_name

    def replace_attr(match):
        prefix = match.group(1)
        attr_name = prefix.split('=', 1)[0].strip().lower()
        if attr_name in {'rel', 'as', 'http-equiv'}:
            return match.group(0)
        if attr_name == 'integrity':
            return '' if drop_integrity else match.group(0)

        if match.group(2) is not None:
            raw_val, quote_char = match.group(2), '"'
        elif match.group(3) is not None:
            raw_val, quote_char = match.group(3), "'"
        else:
            raw_val, quote_char = match.group(4), '"'

        unescaped = html.unescape(raw_val)
        if attr_name == 'style':
            new_val = rewrite_css_for_proxy(unescaped, base_url, target_origin, short_code)
        elif attr_name == 'content':
            if not is_meta_refresh:
                return match.group(0)
            m_ref = META_REFRESH_RE.match(unescaped)
            if not m_ref:
                return match.group(0)
            ref_url = to_proxy_url(m_ref.group(3), base_url, target_origin, short_code, same_origin_only=True)
            new_val = f'{m_ref.group(1)}{m_ref.group(2)}{ref_url}{m_ref.group(2)}'
        elif attr_name == 'srcset':
            if tag_name not in {'img', 'source', 'link'}:
                return match.group(0)
            new_val = rewrite_srcset(unescaped, base_url, target_origin, short_code)
        elif attr_name in {'href', 'xlink:href'}:
            if tag_name not in {'link', 'a', 'area', 'image', 'use'}:
                return match.group(0)
            new_val = to_proxy_url(unescaped, base_url, target_origin, short_code, same_origin_only=same_origin_only)
        elif attr_name == 'action':
            if tag_name != 'form':
                return match.group(0)
            new_val = to_proxy_url(unescaped, base_url, target_origin, short_code, same_origin_only=True)
        elif attr_name == 'data':
            if tag_name != 'object':
                return match.group(0)
            new_val = to_proxy_url(unescaped, base_url, target_origin, short_code, same_origin_only=False)
        elif attr_name in {'src', 'poster'}:
            if tag_name not in {'script', 'img', 'source', 'video', 'audio', 'iframe', 'embed', 'track'}:
                return match.group(0)
            new_val = to_proxy_url(unescaped, base_url, target_origin, short_code, same_origin_only=same_origin_only)
        else:
            return match.group(0)

        escaped = html.escape(new_val, quote=True) if quote_char == '"' else new_val.replace("'", '&#x27;')
        return f'{prefix}{quote_char}{escaped}{quote_char}'

    return ATTR_RE.sub(replace_attr, tag_text), base_url, tag_name


def rewrite_html_for_proxy(html_text, current_url, target_origin, short_code, canonical_entry_url=''):
    effective_base = current_url
    shim = build_proxy_shim_script(
        short_code=short_code,
        current_upstream_url=current_url,
        target_origin=target_origin,
        canonical_entry_url=canonical_entry_url or current_url,
    )
    output = []
    last_end = 0
    shim_injected = False
    html_tag_output_idx = None

    for match in HTML_TOKEN_RE.finditer(html_text):
        output.append(html_text[last_end:match.start()])
        last_end = match.end()

        if match.group(1) is not None:
            output.append(match.group(1))
        elif match.group(2) is not None:
            script_open, script_body, script_close = match.group(2), match.group(3), match.group(4)
            rewritten_open, _, _ = _rewrite_open_tag(script_open, effective_base, target_origin, short_code)
            output.append(f'{rewritten_open}{script_body}{script_close}')
        elif match.group(5) is not None:
            style_open, style_body, style_close = match.group(5), match.group(6), match.group(7)
            rewritten_stage_open, _, _ = _rewrite_open_tag(style_open, effective_base, target_origin, short_code)
            rewritten_css = rewrite_css_for_proxy(style_body, effective_base, target_origin, short_code)
            output.append(f'{rewritten_stage_open}{rewritten_css}{style_close}')
        elif match.group(8) is not None:
            rewritten_tag, effective_base, tag_name = _rewrite_open_tag(
                match.group(8), effective_base, target_origin, short_code
            )
            output.append(rewritten_tag)
            if tag_name == 'head' and not shim_injected:
                output.append(shim)
                shim_injected = True
            elif tag_name == 'html' and html_tag_output_idx is None:
                html_tag_output_idx = len(output)

    output.append(html_text[last_end:])

    if not shim_injected:
        if html_tag_output_idx is not None:
            output.insert(html_tag_output_idx, f'<head>{shim}</head>')
        else:
            output.insert(0, shim)

    return ''.join(output)


def _decode_text(raw_bytes, content_type):
    charset_match = CHARSET_RE.search(content_type or '')
    candidates = []
    if charset_match:
        candidates.append(charset_match.group(1).strip('"\''))
    meta_match = META_CHARSET_RE.search(raw_bytes[:2048])
    if meta_match:
        try:
            candidates.append(meta_match.group(1).decode('ascii', errors='ignore'))
        except Exception:
            pass
    candidates.extend(['utf-8', 'gb18030'])
    for enc in candidates:
        if not enc:
            continue
        try:
            return raw_bytes.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw_bytes.decode('utf-8', errors='replace')


def _upstream_cookie_prefix(secret_key, short_code, cookie_scope):
    if not secret_key or not short_code or not cookie_scope:
        return ''
    digest = hmac.new(
        secret_key.encode('utf-8'),
        f'{short_code}:{cookie_scope.lower()}'.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:10]
    return f'{UPSTREAM_COOKIE_PREFIX}{digest}_'


def _candidate_cookie_scopes(hostname):
    """Return RFC 6265 matching scopes from least specific (.example.com) to host-specific (www.example.com)."""
    host = (hostname or '').strip('.').lower()
    if not host:
        return []
    try:
        ipaddress.ip_address(host.strip('[]'))
        return [host]
    except ValueError:
        pass
    labels = host.split('.')
    scopes = []
    # Domain-attribute scopes (.example.com) require at least 2 labels
    for idx in range(len(labels) - 2, -1, -1):
        parent = '.'.join(labels[idx:])
        if '.' in parent:
            scopes.append(f'.{parent}')
    scopes.append(host)
    return scopes


def _resolve_cookie_scope(request_hostname, raw_domain_attr):
    host = (request_hostname or '').strip('.').lower()
    if not raw_domain_attr:
        return host
    dom = raw_domain_attr.strip().lstrip('.').lower()
    if not dom or '.' not in dom:
        return host
    try:
        ipaddress.ip_address(host.strip('[]'))
        return host
    except ValueError:
        pass
    if host == dom or host.endswith(f'.{dom}'):
        return f'.{dom}'
    return None


def _extract_scoped_upstream_cookies(secret_key, short_code, hostname, extra_scope_jars=None):
    merged = {}
    scopes = _candidate_cookie_scopes(hostname)
    if _env_flag('ENABLE_PROXY_COOKIES', True) and secret_key and scopes:
        for scope in scopes:
            prefix = _upstream_cookie_prefix(secret_key, short_code, scope)
            if not prefix:
                continue
            for k, v in request.cookies.items():
                if k.startswith(prefix):
                    orig_name = k[len(prefix):]
                    if SAFE_COOKIE_NAME_RE.fullmatch(orig_name):
                        merged[orig_name] = v
    if extra_scope_jars:
        for scope in scopes:
            scope_jar = extra_scope_jars.get(scope)
            if scope_jar:
                for c_name, c_val in scope_jar.items():
                    if c_val is None:
                        merged.pop(c_name, None)
                    else:
                        merged[c_name] = c_val
    return merged


def _extract_upstream_set_cookie_headers(resp):
    raw_headers = getattr(getattr(resp, 'raw', None), 'headers', None)
    if raw_headers is not None:
        if hasattr(raw_headers, 'getlist'):
            return list(raw_headers.getlist('Set-Cookie'))
        if hasattr(raw_headers, 'get_all'):
            return list(raw_headers.get_all('Set-Cookie') or [])
    single = _ci_get(resp.headers, 'Set-Cookie', '')
    return [single] if single else []


def _parse_set_cookie_pairs(set_cookie_headers, request_hostname):
    parsed_items = []
    for header_val in set_cookie_headers:
        if not header_val:
            continue
        jar = SimpleCookie()
        try:
            jar.load(header_val)
        except CookieError:
            continue
        for morsel_name, morsel in jar.items():
            if not SAFE_COOKIE_NAME_RE.fullmatch(morsel_name):
                continue
            scope = _resolve_cookie_scope(request_hostname, morsel['domain'])
            if not scope:
                continue
            max_age = None
            raw_max_age = morsel['max-age']
            if raw_max_age != '':
                try:
                    max_age = int(raw_max_age)
                except ValueError:
                    max_age = None
            parsed_items.append((scope, morsel_name, morsel.value, max_age))
    return parsed_items


def _reconstruct_upstream_referer(short_code, frontend_origin, canonical_entry_url=''):
    client_ref = request.headers.get('Referer')
    if client_ref:
        ref_parsed = urlparse(client_ref)
        if not ref_parsed.netloc or ref_parsed.netloc == request.host:
            ref_path = ref_parsed.path or ''
            p_prefix = f'/_p/{short_code}'
            if ref_path == f'/{short_code}':
                base = canonical_entry_url or f'{frontend_origin}/'
                if ref_parsed.query:
                    sep = '&' if '?' in base else '?'
                    return f'{base}{sep}{ref_parsed.query}'
                return base
            if ref_path == p_prefix or ref_path.startswith(f'{p_prefix}/'):
                sub = ref_path[len(p_prefix):] or '/'
                qs = f'?{ref_parsed.query}' if ref_parsed.query else ''
                return f'{frontend_origin}{sub}{qs}'
    return canonical_entry_url or f'{frontend_origin}/'


def build_upstream_request_headers(
    target_url,
    frontend_origin='',
    canonical_entry_url='',
    is_cross_origin=False,
    allow_authorization=False,
    cookie_map=None,
):
    headers = {}
    for key, value in request.headers.items():
        lower_k = key.lower()
        if lower_k in FORWARDED_REQUEST_HEADERS:
            headers[key] = value
        elif lower_k == 'authorization' and allow_authorization:
            headers[key] = value

    headers['User-Agent'] = request.headers.get('User-Agent') or DEFAULT_USER_AGENT
    headers['Accept-Encoding'] = 'gzip, deflate, br' if _has_brotli() else 'gzip, deflate'

    parsed_target = urlparse(target_url)
    target_origin = f'{parsed_target.scheme}://{parsed_target.netloc}'
    effective_front_origin = _normalize_origin(frontend_origin) or target_origin

    if is_cross_origin or effective_front_origin != target_origin:
        if request.method not in {'GET', 'HEAD'} or 'Origin' in request.headers:
            headers['Origin'] = effective_front_origin
        headers['Referer'] = f'{effective_front_origin}/'
    else:
        if request.method not in {'GET', 'HEAD'}:
            headers['Origin'] = effective_front_origin
        if canonical_entry_url:
            headers['Referer'] = canonical_entry_url
        else:
            headers['Referer'] = f'{effective_front_origin}/'
        req_ref = request.headers.get('Referer', '')
        if '/_p/' in req_ref:
            ref_path = urlparse(req_ref).path or ''
            parts = ref_path.split('/', 3)
            if len(parts) >= 3 and parts[1] == '_p':
                headers['Referer'] = _reconstruct_upstream_referer(
                    parts[2], effective_front_origin, canonical_entry_url
                )

    if cookie_map:
        cookie_str = '; '.join(f'{k}={v}' for k, v in list(cookie_map.items())[:20])
        if len(cookie_str) <= 4096:
            headers['Cookie'] = cookie_str

    return headers


_BROTLI_AVAILABLE = None


def _has_brotli():
    global _BROTLI_AVAILABLE
    if _BROTLI_AVAILABLE is None:
        try:
            import brotli  # noqa: F401
            _BROTLI_AVAILABLE = True
        except ImportError:
            try:
                import brotlicffi  # noqa: F401
                _BROTLI_AVAILABLE = True
            except ImportError:
                _BROTLI_AVAILABLE = False
    return _BROTLI_AVAILABLE


def extract_raw_subpath_and_query(route_prefix, decoded_subpath=''):
    raw_uri = request.environ.get('RAW_URI') or request.environ.get('REQUEST_URI')
    raw_query = request.environ.get('QUERY_STRING', '')
    if raw_uri:
        raw_path = raw_uri.split('?', 1)[0]
        if raw_path.startswith(route_prefix):
            suffix = raw_path[len(route_prefix):]
            if not suffix:
                suffix = '/'
            elif not suffix.startswith('/'):
                suffix = f'/{suffix}'
            return suffix, raw_query
    encoded = quote(decoded_subpath.lstrip('/'), safe="/:@!$&'()*+,;=-._~")
    if request.path.endswith('/') and encoded and not encoded.endswith('/'):
        encoded = f'{encoded}/'
    return f'/{encoded}' if encoded else '/', raw_query


def _ci_get(headers, name, default=''):
    val = headers.get(name)
    if val is not None:
        return val
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return default


def _read_bounded_request_body(max_req_bytes):
    content_len = request.content_length
    if content_len is not None and content_len > max_req_bytes:
        abort(413)
    stream = request.stream
    buf = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_req_bytes:
            abort(413)
    return bytes(buf)


def execute_proxy_request(
    target_url,
    entry_origin,
    short_code,
    set_session_cookie=False,
    secret_key='',
    target_validator=is_public_proxy_target,
    canonical_entry_url='',
    is_cross_origin=False,
):
    if is_blocked_worker_request():
        abort(403)

    session = get_proxy_session()
    method = request.method.upper()
    max_req_bytes = proxy_max_request_bytes()
    req_body = _read_bounded_request_body(max_req_bytes) if method in {'POST', 'PUT', 'PATCH', 'DELETE'} else None
    max_bytes = proxy_max_bytes()

    sec_dest = (request.headers.get('Sec-Fetch-Dest') or '').strip().lower()
    sec_mode = (request.headers.get('Sec-Fetch-Mode') or '').strip().lower()
    is_top_navigation = sec_dest == 'document' or sec_mode == 'navigate'
    allow_auth = not is_top_navigation

    initial_parsed = urlparse(target_url)
    initial_origin = f'{initial_parsed.scheme}://{initial_parsed.netloc}'
    effective_front_origin = get_effective_target_origin(secret_key, short_code, entry_origin)

    hop_cookies_by_scope = {}
    collected_cookies_for_browser = []

    current_url = target_url
    upstream = None
    prev_pin_state = getattr(_pin_dns_tls, 'enforce_public_ip', True)
    _pin_dns_tls.enforce_public_ip = target_validator is is_public_proxy_target
    try:
        for _ in range(10):
            parsed = urlparse(current_url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
                abort(400)
            try:
                port = parsed.port
            except ValueError:
                abort(400)
            if not _env_flag('PROXY_ALLOW_CUSTOM_PORTS', False) and port not in {None, 80, 443}:
                abort(403)
            if not target_validator(current_url):
                abort(403)

            host_key = parsed.hostname.lower()
            current_origin = f'{parsed.scheme}://{parsed.netloc}'
            hop_allow_auth = allow_auth and (current_origin == initial_origin)
            cookie_map = _extract_scoped_upstream_cookies(
                secret_key, short_code, host_key, extra_scope_jars=hop_cookies_by_scope
            )

            req_headers = build_upstream_request_headers(
                current_url,
                frontend_origin=effective_front_origin,
                canonical_entry_url=canonical_entry_url,
                is_cross_origin=is_cross_origin,
                allow_authorization=hop_allow_auth,
                cookie_map=cookie_map,
            )
            resp = session.request(
                method=method,
                url=current_url,
                headers=req_headers,
                data=req_body,
                timeout=(5.0, 30.0),
                allow_redirects=False,
                stream=True,
            )

            set_cookie_headers = _extract_upstream_set_cookie_headers(resp)
            if set_cookie_headers:
                parsed_pairs = _parse_set_cookie_pairs(set_cookie_headers, host_key)
                for c_scope, c_name, c_val, c_max_age in parsed_pairs:
                    scope_jar = hop_cookies_by_scope.setdefault(c_scope, {})
                    if c_max_age is not None and c_max_age <= 0:
                        scope_jar[c_name] = None
                    else:
                        scope_jar[c_name] = c_val
                    collected_cookies_for_browser.append((c_scope, c_name, c_val, c_max_age))

            if resp.is_redirect:
                location = _ci_get(resp.headers, 'Location', '')
                if not location:
                    upstream = resp
                    break
                current_url = urljoin(current_url, location)
                resp.close()
                if resp.status_code in {301, 302, 303} and method not in {'GET', 'HEAD'}:
                    method = 'GET'
                    req_body = None
                continue
            upstream = resp
            break
        else:
            raise requests.TooManyRedirects('上游重定向次数超过上限')

        if upstream is None:
            raise requests.ConnectionError('未能获取上游响应')

        declared_len = _ci_get(upstream.headers, 'Content-Length', '')
        if declared_len:
            try:
                if int(declared_len) > max_bytes:
                    upstream.close()
                    abort(413)
            except ValueError:
                pass

        resp_headers = Headers()
        for k, v in upstream.headers.items():
            if k.lower() in PASSTHROUGH_RESPONSE_HEADERS:
                clean_v = re.sub(r'[\x00-\x08\x0a-\x1f\x7f]', '', str(v))
                resp_headers.set(k, clean_v)
        content_type = _ci_get(upstream.headers, 'Content-Type', '')
        lower_ct = content_type.lower()
        final_parsed = urlparse(current_url)
        final_origin = f'{final_parsed.scheme}://{final_parsed.netloc}'

        if set_session_cookie and not is_cross_origin:
            effective_target_origin = final_origin
            if final_origin != entry_origin:
                remember_resolved_origin(short_code, entry_origin, final_origin)
        else:
            effective_target_origin = effective_front_origin

        if final_parsed.path.lower().endswith('.wasm') and (not lower_ct or 'octet-stream' in lower_ct):
            resp_headers.set('Content-Type', 'application/wasm')
            content_type = 'application/wasm'
            lower_ct = content_type.lower()

        status_code = upstream.status_code
        is_html_or_css = (
            'text/html' in lower_ct
            or 'application/xhtml+xml' in lower_ct
            or 'text/css' in lower_ct
        )

        if method == 'HEAD' or status_code in {204, 304}:
            upstream.close()
            flask_resp = Response(b'', status=status_code, headers=resp_headers)
        elif is_html_or_css:
            rewrite_cap = proxy_rewrite_max_bytes()
            buf = bytearray()
            for chunk in upstream.iter_content(64 * 1024):
                buf.extend(chunk)
                if len(buf) > rewrite_cap:
                    upstream.close()
                    abort(413)
            upstream.close()
            text = _decode_text(bytes(buf), content_type)
            if 'text/css' in lower_ct:
                rewritten = rewrite_css_for_proxy(text, current_url, effective_target_origin, short_code)
                resp_headers.set('Content-Type', 'text/css; charset=utf-8')
            else:
                rewritten = rewrite_html_for_proxy(
                    text,
                    current_url,
                    effective_target_origin,
                    short_code,
                    canonical_entry_url=canonical_entry_url or current_url,
                )
                resp_headers.set('Content-Type', 'text/html; charset=utf-8')
            resp_headers.pop('ETag', None)
            flask_resp = Response(rewritten.encode('utf-8'), status=status_code, headers=resp_headers)
        else:
            is_sse = 'text/event-stream' in lower_ct
            sse_sem = _get_sse_semaphore() if is_sse else None
            if sse_sem is not None and not sse_sem.acquire(blocking=False):
                upstream.close()
                return Response(
                    '代理长连接并发已达上限，请稍后重试。',
                    status=503,
                    mimetype='text/plain',
                    headers={'Cache-Control': 'no-store'},
                )

            try:
                upstream_encoding = _ci_get(upstream.headers, 'Content-Encoding', '').lower().strip()
                client_accepts_gzip = 'gzip' in (request.headers.get('Accept-Encoding') or '').lower()
                raw_obj = getattr(upstream, 'raw', None)
                if (
                    upstream_encoding == 'gzip'
                    and client_accepts_gzip
                    and raw_obj is not None
                    and hasattr(raw_obj, 'stream')
                ):
                    resp_headers.set('Content-Encoding', 'gzip')
                    chunk_source = raw_obj.stream(64 * 1024, decode_content=False)
                else:
                    if upstream_encoding:
                        resp_headers.pop('ETag', None)
                    chunk_source = upstream.iter_content(64 * 1024)

                if is_sse:
                    pre_limit = 0
                elif not declared_len and max_bytes <= 2 * 1024 * 1024:
                    pre_limit = max_bytes + 1
                else:
                    pre_limit = min(max_bytes + 1, 64 * 1024)

                pre_buf = bytearray()
                it = iter(chunk_source)
                exhausted = False
                while len(pre_buf) < pre_limit:
                    try:
                        chunk = next(it)
                    except StopIteration:
                        exhausted = True
                        break
                    if chunk:
                        pre_buf.extend(chunk)
                        if len(pre_buf) > max_bytes:
                            upstream.close()
                            if sse_sem is not None:
                                sse_sem.release()
                            abort(413)
            except Exception:
                upstream.close()
                if sse_sem is not None:
                    sse_sem.release()
                raise

            if exhausted:
                upstream.close()
                if sse_sem is not None:
                    sse_sem.release()
                flask_resp = Response(bytes(pre_buf), status=status_code, headers=resp_headers)
            else:
                def generate(initial_bytes, chunk_iter, held_sem):
                    total = len(initial_bytes)
                    try:
                        if initial_bytes:
                            yield initial_bytes
                        for chunk in chunk_iter:
                            if not chunk:
                                continue
                            total += len(chunk)
                            if total > max_bytes:
                                break
                            yield chunk
                    except (requests.RequestException, Urllib3HTTPError):
                        return
                    finally:
                        upstream.close()
                        if held_sem is not None:
                            held_sem.release()

                flask_resp = Response(
                    stream_with_context(generate(bytes(pre_buf), it, sse_sem)),
                    status=status_code,
                    headers=resp_headers,
                )

        flask_resp._is_proxied = True
        should_issue_session = set_session_cookie or (
            not is_cross_origin and method == 'GET' and 'text/html' in lower_ct
        )
        if should_issue_session and secret_key:
            resolved_to_save = effective_target_origin if effective_target_origin != entry_origin else ''
            cookie_val = build_proxy_cookie(
                secret_key,
                request.cookies.get(PROXY_COOKIE_NAME),
                short_code,
                resolved_origin=resolved_to_save,
            )
            flask_resp.set_cookie(
                PROXY_COOKIE_NAME,
                cookie_val,
                max_age=proxy_session_ttl(),
                httponly=True,
                samesite='Lax',
                secure=request.is_secure,
                path='/',
            )

        if _env_flag('ENABLE_PROXY_COOKIES', True) and secret_key and collected_cookies_for_browser:
            for c_scope, c_name, c_val, c_max_age in collected_cookies_for_browser[-15:]:
                prefix = _upstream_cookie_prefix(secret_key, short_code, c_scope)
                scoped_name = f'{prefix}{c_name}'
                if len(scoped_name) + len(c_val) > 2048:
                    continue
                if c_max_age is not None and c_max_age <= 0:
                    flask_resp.delete_cookie(scoped_name, path='/')
                else:
                    effective_age = min(c_max_age, proxy_session_ttl()) if c_max_age else proxy_session_ttl()
                    flask_resp.set_cookie(
                        scoped_name,
                        c_val,
                        max_age=effective_age,
                        httponly=True,
                        samesite='Lax',
                        secure=request.is_secure,
                        path='/',
                    )

        return flask_resp
    except UnsafeProxyTargetError:
        if upstream is not None:
            upstream.close()
        abort(403)
    except Urllib3HTTPError as exc:
        if upstream is not None:
            upstream.close()
        if isinstance(exc.__cause__, UnsafeProxyTargetError) or isinstance(exc.__context__, UnsafeProxyTargetError):
            abort(403)
        raise requests.ConnectionError(str(exc)) from exc
    except requests.RequestException as exc:
        if upstream is not None:
            upstream.close()
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, UnsafeProxyTargetError) or (
            cause is not None
            and (isinstance(cause.__cause__, UnsafeProxyTargetError) or isinstance(cause.__context__, UnsafeProxyTargetError))
        ):
            abort(403)
        raise
    finally:
        _pin_dns_tls.enforce_public_ip = prev_pin_state

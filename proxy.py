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
from urllib.parse import quote, urljoin, urlparse

import requests
from flask import Response, abort, request, stream_with_context
from requests.adapters import HTTPAdapter
from urllib3.exceptions import HTTPError as Urllib3HTTPError
from urllib3.util.retry import Retry
from werkzeug.datastructures import Headers

PROXY_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
PROXY_COOKIE_NAME = '__syu_proxy'
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
    'authorization',
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

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/131.0.0.0 Safari/537.36'
)

NON_HTTP_SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.-]*):')
CHARSET_RE = re.compile(r'charset=([^\s;]+)', re.IGNORECASE)
META_CHARSET_RE = re.compile(rb'<meta[^>]+charset=["\']?\s*([a-zA-Z0-9._-]+)', re.IGNORECASE)

HTML_TOKEN_RE = re.compile(
    r'(?is)'
    r'(<!--.*?-->)'
    r'|(<script\b[^>]*>)(.*?)(</script\s*>)'
    r'|(<style\b[^>]*>)(.*?)(</style\s*>)'
    r'|(<(?:base|link|img|source|video|audio|iframe|embed|track|form|a|area)\b[^>]*>)'
)
TAG_NAME_RE = re.compile(r'^<\s*([a-zA-Z0-9]+)')
ATTR_RE = re.compile(
    r"""(\b(?:href|src|poster|action|srcset|integrity|rel|as)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""",
    re.IGNORECASE,
)
HEAD_OPEN_RE = re.compile(r'<head\b[^>]*>', re.IGNORECASE)
HTML_OPEN_RE = re.compile(r'<html\b[^>]*>', re.IGNORECASE)
CSS_URL_RE = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']+))\s*\)""", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r"""(@import\s+)(?:"([^"]+)"|'([^']+)')""", re.IGNORECASE)


class _RejectAllCookiesPolicy(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


_session_lock = threading.Lock()
_shared_session = None
_dns_cache_lock = threading.Lock()
_dns_cache = {}
DNS_CACHE_TTL = 60.0


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
                adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=retry_strategy)
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                _shared_session = session
    return _shared_session


def clear_dns_cache():
    with _dns_cache_lock:
        _dns_cache.clear()


def is_public_proxy_target(url):
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    now = time.monotonic()
    with _dns_cache_lock:
        cached = _dns_cache.get(hostname)
        if cached and cached[1] > now:
            return cached[0]
    resolved_ok = False
    try:
        addresses = socket.getaddrinfo(hostname, None)
        resolved_ok = bool(addresses)
        allowed = resolved_ok and all(ipaddress.ip_address(addr[4][0]).is_global for addr in addresses)
    except (socket.gaierror, ValueError):
        allowed = False
    if resolved_ok:
        with _dns_cache_lock:
            if len(_dns_cache) > 1024:
                _dns_cache.clear()
            _dns_cache[hostname] = (allowed, now + DNS_CACHE_TTL)
    return allowed


def proxy_max_bytes():
    try:
        mb = int(os.environ.get('PROXY_MAX_MB', '50'))
    except ValueError:
        mb = 50
    return max(1, mb) * 1024 * 1024


def proxy_rewrite_max_bytes():
    return min(proxy_max_bytes(), 15 * 1024 * 1024)


def proxy_session_ttl():
    try:
        return max(60, int(os.environ.get('PROXY_SESSION_TTL', '21600')))
    except ValueError:
        return 21600


def _sign_cookie_payload(secret_key, payload):
    return hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()[:32]


def parse_proxy_cookie(secret_key, raw_cookie):
    if not raw_cookie or '.' not in raw_cookie:
        return []
    parts = raw_cookie.split('.')
    if len(parts) != 3:
        return []
    codes_part, ts_str, sig = parts
    expected = _sign_cookie_payload(secret_key, f'{codes_part}.{ts_str}')
    if not hmac.compare_digest(sig, expected):
        return []
    try:
        issued = int(ts_str)
    except ValueError:
        return []
    if issued + proxy_session_ttl() < int(time.time()):
        return []
    return [c for c in codes_part.split(':') if c]


def build_proxy_cookie(secret_key, existing_cookie, short_code):
    codes = [c for c in parse_proxy_cookie(secret_key, existing_cookie) if c != short_code]
    codes.append(short_code)
    codes = codes[-10:]
    ts_str = str(int(time.time()))
    codes_part = ':'.join(codes)
    sig = _sign_cookie_payload(secret_key, f'{codes_part}.{ts_str}')
    return f'{codes_part}.{ts_str}.{sig}'


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


def has_valid_proxy_context(secret_key, short_code, short_code_pattern):
    if extract_referer_short_code(short_code_pattern) == short_code:
        return True
    codes = parse_proxy_cookie(secret_key, request.cookies.get(PROXY_COOKIE_NAME))
    return short_code in codes


def to_proxy_url(raw_url, base_url, target_origin, short_code, same_origin_only=False):
    if raw_url is None:
        return raw_url
    value = raw_url.strip()
    if not value or value.startswith('#'):
        return raw_url
    p_prefix = f'/_p/{short_code}'
    px_prefix = f'/_px/{short_code}'
    if value == p_prefix or value.startswith(f'{p_prefix}/') or value.startswith(f'{p_prefix}?') or value.startswith(f'{px_prefix}/'):
        return raw_url

    scheme_match = NON_HTTP_SCHEME_RE.match(value)
    if scheme_match and scheme_match.group(1).lower() not in {'http', 'https'}:
        return raw_url

    resolved = urljoin(base_url, value)
    parsed = urlparse(resolved)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
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


def build_proxy_shim_script(short_code, entry_url, target_origin):
    parsed_entry = urlparse(entry_url)
    entry_path = parsed_entry.path or '/'
    config_json = json.dumps(
        {
            'code': short_code,
            'entryUrl': entry_url,
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
    return CFG.pPrefix + suffix;
  }
  if (sameOriginOnly) return raw;
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

if (typeof window.trustedTypes !== 'undefined' && window.trustedTypes && window.trustedTypes.createPolicy) {
  const origCreatePolicy = window.trustedTypes.createPolicy.bind(window.trustedTypes);
  window.trustedTypes.createPolicy = function (name, rules) {
    if (rules && typeof rules === 'object') {
      const wrapped = Object.assign({}, rules);
      if (typeof rules.createScriptURL === 'function') {
        const fn = rules.createScriptURL;
        wrapped.createScriptURL = function (input) {
          const out = fn.apply(this, arguments);
          return rewriteUrl(out, false);
        };
      }
      if (typeof rules.createURL === 'function') {
        const fn = rules.createURL;
        wrapped.createURL = function (input) {
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
    return new OrigWorker(isTrusted ? url : rewriteUrl(url, false), opts);
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
      } else if (attr === 'href') {
        if (tag === 'link' && !shouldSkipLinkElement(this)) {
          value = rewriteUrl(value, false);
        } else if (tag === 'a' || tag === 'area') {
          value = rewriteUrl(value, true);
        }
      } else if (attr === 'srcset') {
        value = rewriteSrcset(String(value));
      } else if (attr === 'action' && tag === 'form') {
        value = rewriteUrl(value, true);
      }
    }
    return origSetAttr.call(this, name, value);
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
wrapUrlProp(typeof HTMLFormElement !== 'undefined' && HTMLFormElement.prototype, 'action', true);

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
        val = match.group(2) if match.group(2) is not None else (match.group(3) if match.group(3) is not None else match.group(4))
        attrs[key] = html.unescape(val or '')
    return attrs


def _rewrite_open_tag(tag_text, base_url, target_origin, short_code):
    name_match = TAG_NAME_RE.match(tag_text)
    if not name_match:
        return tag_text, base_url
    tag_name = name_match.group(1).lower()
    attrs = _extract_attr_map(tag_text)

    if tag_name == 'base':
        href = attrs.get('href', '').strip()
        next_base = urljoin(base_url, href) if href else base_url
        return '', next_base

    rel_tokens = set(attrs.get('rel', '').lower().split())
    as_val = attrs.get('as', '').lower().strip()
    if tag_name == 'link' and rel_tokens:
        if rel_tokens <= {'preconnect', 'dns-prefetch'}:
            href = attrs.get('href', '').strip()
            if href and urlparse(urljoin(base_url, href)).netloc != urlparse(target_origin).netloc:
                return '', base_url
            return tag_text, base_url
        if rel_tokens <= {'canonical', 'alternate'}:
            return tag_text, base_url

    drop_integrity = tag_name == 'link' and ('stylesheet' in rel_tokens or as_val == 'style')
    same_origin_only = tag_name in {'a', 'area', 'form', 'iframe'}

    def replace_attr(match):
        prefix = match.group(1)
        attr_name = prefix.split('=', 1)[0].strip().lower()
        if attr_name in {'rel', 'as'}:
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
        if attr_name == 'srcset':
            new_val = rewrite_srcset(unescaped, base_url, target_origin, short_code)
        elif attr_name == 'href' and tag_name not in {'link', 'a', 'area'}:
            return match.group(0)
        elif attr_name == 'action' and tag_name != 'form':
            return match.group(0)
        else:
            new_val = to_proxy_url(unescaped, base_url, target_origin, short_code, same_origin_only=same_origin_only)

        escaped = html.escape(new_val, quote=True) if quote_char == '"' else new_val.replace("'", '&#x27;')
        return f'{prefix}{quote_char}{escaped}{quote_char}'

    return ATTR_RE.sub(replace_attr, tag_text), base_url


def rewrite_html_for_proxy(html_text, entry_url, target_origin, short_code):
    effective_base = entry_url
    output = []
    last_end = 0

    for match in HTML_TOKEN_RE.finditer(html_text):
        output.append(html_text[last_end:match.start()])
        last_end = match.end()

        if match.group(1) is not None:
            output.append(match.group(1))
        elif match.group(2) is not None:
            script_open, script_body, script_close = match.group(2), match.group(3), match.group(4)
            rewritten_open, _ = _rewrite_open_tag(script_open, effective_base, target_origin, short_code)
            output.append(f'{rewritten_open}{script_body}{script_close}')
        elif match.group(5) is not None:
            style_open, style_body, style_close = match.group(5), match.group(6), match.group(7)
            rewritten_css = rewrite_css_for_proxy(style_body, effective_base, target_origin, short_code)
            output.append(f'{style_open}{rewritten_css}{style_close}')
        elif match.group(8) is not None:
            rewritten_tag, effective_base = _rewrite_open_tag(match.group(8), effective_base, target_origin, short_code)
            output.append(rewritten_tag)

    output.append(html_text[last_end:])
    rewritten_html = ''.join(output)

    shim = build_proxy_shim_script(short_code, entry_url, target_origin)
    head_match = HEAD_OPEN_RE.search(rewritten_html)
    if head_match:
        idx = head_match.end()
        return f'{rewritten_html[:idx]}{shim}{rewritten_html[idx:]}'
    html_match = HTML_OPEN_RE.search(rewritten_html)
    if html_match:
        idx = html_match.end()
        return f'{rewritten_html[:idx]}<head>{shim}</head>{rewritten_html[idx:]}'
    return f'{shim}{rewritten_html}'


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


def build_upstream_request_headers(target_url):
    headers = {}
    for key, value in request.headers.items():
        if key.lower() in FORWARDED_REQUEST_HEADERS:
            headers[key] = value
    headers['User-Agent'] = request.headers.get('User-Agent') or DEFAULT_USER_AGENT
    headers['Accept-Encoding'] = 'gzip, deflate'
    parsed = urlparse(target_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    if request.method not in {'GET', 'HEAD'}:
        headers['Origin'] = origin
    headers['Referer'] = f'{origin}/'
    return headers


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


def execute_proxy_request(
    target_url,
    entry_origin,
    short_code,
    set_session_cookie=False,
    secret_key='',
    target_validator=is_public_proxy_target,
):
    session = get_proxy_session()
    method = request.method.upper()
    req_body = request.get_data(cache=False) if method in {'POST', 'PUT', 'PATCH', 'DELETE'} else None
    max_bytes = proxy_max_bytes()

    current_url = target_url
    upstream = None
    try:
        for _ in range(10):
            parsed = urlparse(current_url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
                abort(400)
            if not target_validator(current_url):
                abort(403)
            req_headers = build_upstream_request_headers(current_url)
            resp = session.request(
                method=method,
                url=current_url,
                headers=req_headers,
                data=req_body,
                timeout=(5.0, 30.0),
                allow_redirects=False,
                stream=True,
            )
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
        effective_target_origin = final_origin if set_session_cookie else entry_origin

        if final_parsed.path.lower().endswith('.wasm') and (not lower_ct or 'octet-stream' in lower_ct):
            resp_headers.set('Content-Type', 'application/wasm')
            content_type = 'application/wasm'
            lower_ct = content_type.lower()

        status_code = upstream.status_code
        if method == 'HEAD' or status_code in {204, 304}:
            upstream.close()
            flask_resp = Response(b'', status=status_code, headers=resp_headers)
        elif 'text/html' in lower_ct or 'application/xhtml+xml' in lower_ct or 'text/css' in lower_ct:
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
                rewritten = rewrite_html_for_proxy(text, current_url, effective_target_origin, short_code)
                resp_headers.set('Content-Type', 'text/html; charset=utf-8')
            resp_headers.pop('ETag', None)
            flask_resp = Response(rewritten.encode('utf-8'), status=status_code, headers=resp_headers)
        else:
            upstream_encoding = _ci_get(upstream.headers, 'Content-Encoding', '').lower().strip()
            client_accepts_gzip = 'gzip' in (request.headers.get('Accept-Encoding') or '').lower()
            raw_obj = getattr(upstream, 'raw', None)
            if upstream_encoding == 'gzip' and client_accepts_gzip and raw_obj is not None and hasattr(raw_obj, 'stream'):
                resp_headers.set('Content-Encoding', 'gzip')
                chunk_source = raw_obj.stream(64 * 1024, decode_content=False)
            else:
                chunk_source = upstream.iter_content(64 * 1024)

            if not declared_len and max_bytes <= 2 * 1024 * 1024:
                pre_limit = max_bytes + 1
            else:
                pre_limit = min(max_bytes + 1, 64 * 1024)
            pre_buf = bytearray()
            it = iter(chunk_source)
            exhausted = False
            try:
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
                            abort(413)
            except Exception:
                upstream.close()
                raise

            if exhausted:
                upstream.close()
                flask_resp = Response(bytes(pre_buf), status=status_code, headers=resp_headers)
            else:
                def generate(initial_bytes, chunk_iter):
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

                flask_resp = Response(
                    stream_with_context(generate(bytes(pre_buf), it)),
                    status=status_code,
                    headers=resp_headers,
                )

        flask_resp._is_proxied = True
        if set_session_cookie and secret_key:
            cookie_val = build_proxy_cookie(secret_key, request.cookies.get(PROXY_COOKIE_NAME), short_code)
            flask_resp.set_cookie(
                PROXY_COOKIE_NAME,
                cookie_val,
                max_age=proxy_session_ttl(),
                httponly=True,
                samesite='Lax',
                secure=request.is_secure,
                path='/',
            )
        return flask_resp
    except Urllib3HTTPError as exc:
        if upstream is not None:
            upstream.close()
        raise requests.ConnectionError(str(exc)) from exc
    except requests.RequestException:
        if upstream is not None:
            upstream.close()
        raise

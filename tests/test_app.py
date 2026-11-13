import os
import re
import tempfile
import unittest
from unittest.mock import patch

TEST_DIR = tempfile.mkdtemp(prefix='shortener-tests-')
os.environ['DATA_DIR'] = TEST_DIR
os.environ['ADMIN_USERNAME'] = 'admin'
os.environ['ADMIN_PASSWORD'] = 'V7!mQ2#zL9@p'
os.environ['COOKIE_SECURE'] = 'false'
os.environ['ENABLE_PROXY'] = 'false'

from app import Link, User, app, db, init_db_and_admin


class FakeUpstreamResponse:
    def __init__(self, body=b'', status_code=200, headers=None):
        self._body = body if isinstance(body, bytes) else body.encode('utf-8')
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.closed = False

    @property
    def is_redirect(self):
        return self.status_code in {301, 302, 303, 307, 308} and 'Location' in self.headers

    def iter_content(self, chunk_size=65536):
        for idx in range(0, len(self._body), chunk_size):
            yield self._body[idx:idx + chunk_size]

    def close(self):
        self.closed = True


def csrf(response):
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    if not match:
        raise AssertionError('CSRF token missing')
    return match.group(1).decode()


class ApplicationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config.update(TESTING=True)
        init_db_and_admin()

    def setUp(self):
        self.client = app.test_client()
        with app.app_context():
            Link.query.delete()
            User.query.filter(User.username != 'admin').delete()
            admin = User.query.filter_by(username='admin').one()
            admin.failed_login_count = 0
            admin.locked_until = None
            db.session.commit()

    def login(self, username, password):
        token = csrf(self.client.get('/login'))
        return self.client.post('/login', data={'username': username, 'password': password, 'csrf_token': token})

    def logout(self):
        token = csrf(self.client.get('/admin'))
        return self.client.post('/logout', data={'csrf_token': token})

    def test_admin_creates_user_and_links_are_isolated(self):
        self.assertEqual(self.login('admin', 'V7!mQ2#zL9@p').status_code, 302)
        token = csrf(self.client.get('/admin/users'))
        response = self.client.post('/admin/users', data={
            'username': 'alice', 'password': 'K8!pR4#vT2@x', 'csrf_token': token
        })
        self.assertEqual(response.status_code, 302)
        token = csrf(self.client.get('/admin'))
        self.client.post('/admin/create', data={
            'original_url': 'https://example.com/admin', 'custom_code': 'admin-link',
            'mode': 'redirect', 'csrf_token': token
        })
        self.logout()
        self.assertEqual(self.login('alice', 'K8!pR4#vT2@x').status_code, 302)
        page = self.client.get('/admin')
        self.assertNotIn(b'admin-link', page.data)
        self.assertEqual(self.client.get('/admin/edit/admin-link').status_code, 404)
        self.assertEqual(self.client.get('/admin/users').status_code, 403)
        token = csrf(page)
        self.client.post('/admin/create', data={
            'original_url': 'https://example.com/alice', 'custom_code': 'alice-link',
            'mode': 'redirect', 'csrf_token': token
        })
        with app.app_context():
            admin_link = Link.query.filter_by(short_code='admin-link').one()
            alice_link = Link.query.filter_by(short_code='alice-link').one()
            self.assertNotEqual(admin_link.owner_id, alice_link.owner_id)

    def test_registration_absent_csrf_and_security_headers(self):
        self.assertEqual(self.client.get('/register').status_code, 404)
        self.assertIn('Content-Security-Policy', self.client.get('/').headers)
        response = self.client.post('/login', data={'username': 'admin', 'password': 'x'})
        self.assertEqual(response.status_code, 302)

    def test_account_locks_after_five_failures(self):
        for _ in range(5):
            self.login('admin', 'wrong-password')
        with app.app_context():
            admin = User.query.filter_by(username='admin').one()
            self.assertIsNotNone(admin.locked_until)
            self.assertGreater(admin.locked_until, __import__('datetime').datetime.now(__import__('datetime').timezone.utc).replace(tzinfo=None))
        self.assertEqual(self.login('admin', 'V7!mQ2#zL9@p').status_code, 401)
        with app.app_context():
            self.assertEqual(User.query.filter_by(username='admin').one().failed_login_count, 5)


    def _create_proxy_link(self, short_code='spa-demo', url='https://app.example.com/s/token-123'):
        with app.app_context():
            admin = User.query.filter_by(username='admin').one()
            link = Link(short_code=short_code, original_url=url, mode='proxy', owner=admin)
            db.session.add(link)
            db.session.commit()

    def test_spa_proxy_rewrites_html_css_and_proxies_subresources_and_cross_origin(self):
        self._create_proxy_link('spa-demo', 'https://app.example.com/s/token-123')
        captured_requests = []

        sample_html = (
            '<!DOCTYPE html><html><head>'
            '<link rel="preconnect" href="https://fonts.googleapis.com">'
            '<link rel="stylesheet" href="/_next/static/css/app.css?dpl=1" integrity="sha384-abc">'
            '<script src="/_next/static/chunks/main.js?dpl=1" async=""></script>'
            '</head><body>'
            '<!--$?--><template id="B:0"></template><!--/$-->'
            '<img src="/logo.svg" srcset="/a.png 1x, https://cdn.example.org/b.png 2x">'
            '<script>self.__next_f.push([1,"/_next/static/css/keep-inline-json.css"])</script>'
            '</body></html>'
        )
        sample_css = (
            '@font-face{src:url(/_next/static/media/inter.woff2?dpl=1) format("woff2");}'
            '.icon{background:url("https://fonts.gstatic.com/s/icon.ttf");}'
        )

        def fake_request(method, url, headers=None, data=None, **_kwargs):
            captured_requests.append((method, url, data))
            if url == 'https://app.example.com/s/token-123':
                return FakeUpstreamResponse(sample_html, 200, {'Content-Type': 'text/html; charset=utf-8'})
            if url == 'https://app.example.com/_next/static/css/app.css?dpl=1':
                return FakeUpstreamResponse(sample_css, 200, {'Content-Type': 'text/css; charset=utf-8'})
            if url == 'https://app.example.com/_next/static/chunks/app/s/%5Btoken%5D/page.js?dpl=1':
                return FakeUpstreamResponse('console.log("ok");', 200, {'Content-Type': 'application/javascript'})
            if url == 'https://app.example.com/_next/static/media/engine.wasm':
                return FakeUpstreamResponse(b'\x00asm\x01\x00\x00\x00', 200, {'Content-Type': 'application/octet-stream'})
            if url.startswith('https://api.example.org/s/token-123/objects/1?'):
                return FakeUpstreamResponse(b'{"ok":true}', 200, {'Content-Type': 'application/json'})
            if url == 'https://api.example.org/telemetry' and method == 'POST':
                return FakeUpstreamResponse(b'{"accepted":true}', 200, {'Content-Type': 'application/json'})
            if url == 'https://app.example.com/_next/static/chunks/lazy.js':
                return FakeUpstreamResponse('window.__lazy=1;', 200, {'Content-Type': 'application/javascript'})
            return FakeUpstreamResponse('not found', 404, {'Content-Type': 'text/html'})

        with patch.dict(os.environ, {'ENABLE_PROXY': 'true'}), patch('app.public_proxy_target', return_value=True), patch(
            'proxy.requests.Session.request', side_effect=fake_request
        ):
            entry = self.client.get('/spa-demo')
            self.assertEqual(entry.status_code, 200)
            html_out = entry.data.decode('utf-8')
            self.assertIn('data-syu-proxy="1"', html_out)
            self.assertIn('src="/_p/spa-demo/_next/static/chunks/main.js?dpl=1"', html_out)
            self.assertIn('href="/_p/spa-demo/_next/static/css/app.css?dpl=1"', html_out)
            self.assertNotIn('integrity=', html_out)
            self.assertNotIn('fonts.googleapis.com', html_out)
            self.assertIn('/_px/spa-demo/https/cdn.example.org/b.png 2x', html_out)
            self.assertIn('<!--$?--><template id="B:0"></template><!--/$-->', html_out)
            self.assertIn('self.__next_f.push([1,"/_next/static/css/keep-inline-json.css"])', html_out)
            self.assertIn("'wasm-unsafe-eval'", entry.headers.get('Content-Security-Policy', ''))
            self.assertNotIn("'wasm-unsafe-eval'", self.client.get('/').headers.get('Content-Security-Policy', ''))

            css_resp = self.client.get('/_p/spa-demo/_next/static/css/app.css?dpl=1')
            self.assertEqual(css_resp.status_code, 200)
            css_out = css_resp.data.decode('utf-8')
            self.assertIn('url(/_p/spa-demo/_next/static/media/inter.woff2?dpl=1)', css_out)
            self.assertIn('url("/_px/spa-demo/https/fonts.gstatic.com/s/icon.ttf")', css_out)

            bracket_resp = self.client.get('/_p/spa-demo/_next/static/chunks/app/s/%5Btoken%5D/page.js?dpl=1')
            self.assertEqual(bracket_resp.status_code, 200)
            self.assertEqual(bracket_resp.data, b'console.log("ok");')

            wasm_resp = self.client.get('/_p/spa-demo/_next/static/media/engine.wasm')
            self.assertEqual(wasm_resp.status_code, 200)
            self.assertEqual(wasm_resp.headers.get('Content-Type'), 'application/wasm')

            raw_qs = 'X-Goog-Credential=svc%40proj.iam%2F2026&sig=abc'
            ext_resp = self.client.get(f'/_px/spa-demo/https/api.example.org/s/token-123/objects/1?{raw_qs}')
            self.assertEqual(ext_resp.status_code, 200)
            self.assertTrue(any(u.endswith(f'/objects/1?{raw_qs}') for _, u, _ in captured_requests))

            post_resp = self.client.post('/_px/spa-demo/https/api.example.org/telemetry', data=b'{"ev":1}')
            self.assertEqual(post_resp.status_code, 200)

            fb_resp = self.client.get('/_next/static/chunks/lazy.js', headers={'Referer': 'http://localhost/spa-demo'})
            self.assertEqual(fb_resp.status_code, 200)
            self.assertEqual(fb_resp.data, b'window.__lazy=1;')

            nav_404 = self.client.get('/missing-code', headers={'Sec-Fetch-Mode': 'navigate'})
            self.assertEqual(nav_404.status_code, 404)

        with app.app_context():
            self.assertEqual(Link.query.filter_by(short_code='spa-demo').one().clicks, 1)

    def test_proxy_security_boundaries_ssrf_open_proxy_and_route_isolation(self):
        self._create_proxy_link('sec-demo', 'https://app.example.com/page')
        fresh_client = app.test_client()

        with patch.dict(os.environ, {'ENABLE_PROXY': 'true', 'PROXY_MAX_MB': '1'}), patch(
            'app.public_proxy_target', side_effect=lambda u: '127.0.0.1' not in u and 'internal' not in u
        ):
            self.assertEqual(
                fresh_client.get('/_px/sec-demo/https/api.example.org/data').status_code,
                403,
            )
            self.assertEqual(
                fresh_client.get(
                    '/_px/sec-demo/https/api.example.org/phish',
                    headers={'Referer': 'http://localhost/sec-demo', 'Sec-Fetch-Mode': 'navigate'},
                ).status_code,
                403,
            )
            with patch(
                'proxy.requests.Session.request',
                return_value=FakeUpstreamResponse(b'', 302, {'Location': 'http://127.0.0.1:8080/secret'}),
            ):
                self.assertEqual(fresh_client.get('/sec-demo').status_code, 403)

            with patch(
                'proxy.requests.Session.request',
                return_value=FakeUpstreamResponse(b'x' * (1024 * 1024 + 10), 200, {'Content-Type': 'application/octet-stream'}),
            ):
                self.assertEqual(fresh_client.get('/_p/sec-demo/huge.bin').status_code, 413)

        self.assertEqual(fresh_client.get('/login', headers={'Sec-Fetch-Dest': 'empty'}).status_code, 403)
        self.assertEqual(fresh_client.get('/admin', headers={'Sec-Fetch-Dest': 'iframe'}).status_code, 403)

        self.assertEqual(self.login('admin', 'V7!mQ2#zL9@p').status_code, 302)
        token = csrf(self.client.get('/admin'))
        self.client.post(
            '/admin/create',
            data={'original_url': 'https://example.com', 'custom_code': '_p', 'mode': 'redirect', 'csrf_token': token},
        )
        with app.app_context():
            self.assertIsNone(Link.query.filter_by(short_code='_p').first())


if __name__ == '__main__':
    unittest.main()

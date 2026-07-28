import os
import re
import tempfile
import unittest

TEST_DIR = tempfile.mkdtemp(prefix='shortener-tests-')
os.environ['DATA_DIR'] = TEST_DIR
os.environ['ADMIN_USERNAME'] = 'admin'
os.environ['ADMIN_PASSWORD'] = 'V7!mQ2#zL9@p'
os.environ['COOKIE_SECURE'] = 'false'
os.environ['ENABLE_PROXY'] = 'false'

from app import Link, User, app, db, init_db_and_admin


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


if __name__ == '__main__':
    unittest.main()

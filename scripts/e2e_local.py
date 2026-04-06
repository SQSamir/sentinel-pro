import os
import tempfile
from fastapi.testclient import TestClient

os.environ['DB_PATH'] = tempfile.mktemp(suffix='.db')
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['ADMIN_USERNAME'] = 'admin'
os.environ['ADMIN_PASSWORD'] = 'admin'
os.environ['CONFIG_BACKUP_DIR'] = tempfile.mkdtemp(prefix='sentinel-bak-')
os.environ['FAIL2BAN_CONFIG'] = tempfile.mktemp(prefix='jail.', suffix='.local')
os.environ['FAIL2BAN_LOG'] = tempfile.mktemp(prefix='fail2ban.', suffix='.log')

from sentinel.main import app


def run():
    c = TestClient(app)
    with c:
        r = c.post('/auth/login', json={'username': 'admin', 'password': 'admin'})
        assert r.status_code == 200, r.text
        token = r.json()['access_token']
        h = {'Authorization': f'Bearer {token}'}

        assert c.get('/auth/me', headers=h).status_code == 200
        assert c.get('/system/health', headers=h).status_code == 200
        assert c.get('/audit', headers=h).status_code == 200
        assert c.get('/auth/sessions', headers=h).status_code == 200

        # Brute-force lockout smoke
        for _ in range(5):
            c.post('/auth/login', json={'username': 'admin', 'password': 'wrong'})
        r = c.post('/auth/login', json={'username': 'admin', 'password': 'wrong'})
        assert r.status_code in (401, 429)

        print('E2E_LOCAL_OK')


if __name__ == '__main__':
    run()

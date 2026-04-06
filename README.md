# SENTINEL PRO

Production-focused fail2ban web panel (FastAPI + dark UI), no 2FA.

## Implemented modules

- JWT auth (access + refresh rotation)
- Brute-force lockout by username+IP
- Session management (`/auth/sessions`, `/auth/logout`, `/auth/logout-all`)
- RBAC: `VIEWER`, `OPERATOR`, `ADMIN`, `SUPERADMIN`
- Fail2ban operations:
  - jails list/detail
  - start/stop/reload
  - ban/unban
  - bulk ban/unban
  - whitelist CRUD
- Config editor:
  - read/write fail2ban config
  - basic validation
  - backup rotation
- Logs:
  - search/filter endpoint
  - export endpoint
  - realtime tail via WebSocket (`/ws/events`)
- Audit log:
  - append-only model
  - hash-chain fields (`prev_hash`, `row_hash`)
  - export endpoint
- System health endpoint (`/system/health`)
- Dark UI pages for all major modules

## Local test

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/e2e_local.py
```

## Docker (target layout `/opt/sentinel-pro`)

```bash
cp -a . /opt/sentinel-pro
cd /opt/sentinel-pro
cat > .env <<'EOF'
SECRET_KEY=<strong-random-secret>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
DB_PATH=/data/sentinel.db
FAIL2BAN_LOG=/var/log/fail2ban.log
FAIL2BAN_CONFIG=/etc/fail2ban/jail.local
EOF

docker compose build
docker compose up -d
```

App listens on `127.0.0.1:8088` (for reverse proxy only).

## Caddy route snippet (`/opt/caddy/Caddyfile`)

```caddy
sentinel.example.com {
    reverse_proxy 127.0.0.1:8088
}
```

Reload Caddy after merge with existing routes:

```bash
cd /opt/caddy
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
```

⚠️ Preserve existing Caddy blocks/apps when adding the route.

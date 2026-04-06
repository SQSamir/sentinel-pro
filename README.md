# SENTINEL PRO

Fail2ban web management panel (FastAPI + vanilla JS).

## Included in this source push

- Auth (JWT access + refresh)
- SQLite users/refresh tokens/audit log/whitelist
- RBAC base (VIEWER/OPERATOR/ADMIN/SUPERADMIN)
- fail2ban-client API wrappers (jails, ban/unban, stats)
- Web UI skeleton (dark theme)
- WebSocket endpoint scaffold
- installer script + systemd service

## Quick run (dev)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn sentinel.main:app --reload --port 8088
```

Open: http://127.0.0.1:8088

Default first-run user (auto-created when DB empty):
- username: `admin`
- password: `admin123`

## Production

Use `scripts/installer.sh` as root.

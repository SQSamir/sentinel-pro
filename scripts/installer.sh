#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/sentinel-pro"
SERVICE_FILE="/etc/systemd/system/sentinel-panel.service"

sudo mkdir -p "$APP_DIR"
sudo cp -r . "$APP_DIR"
cd "$APP_DIR"

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if ! grep -q '^SECRET_KEY=' .env 2>/dev/null; then
  echo "SECRET_KEY=$(openssl rand -hex 64)" | sudo tee -a .env >/dev/null
fi

sudo tee "$SERVICE_FILE" >/dev/null <<UNIT
[Unit]
Description=Sentinel Pro fail2ban panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=-$APP_DIR/.env
ExecStart=$APP_DIR/.venv/bin/uvicorn sentinel.main:app --host 0.0.0.0 --port 8088
Restart=always
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-panel.service

echo "Installed. Open: http://SERVER_IP:8088"
echo "Default admin login: admin / admin (change immediately)"

from pydantic import BaseModel
import os
from pathlib import Path

class Settings(BaseModel):
    app_name: str = "SENTINEL PRO"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8088"))
    secret_key: str = os.getenv("SECRET_KEY", "change-me")
    db_path: str = os.getenv("DB_PATH", "./sentinel.db")
    access_exp_minutes: int = 15
    refresh_exp_days: int = 7
    fail2ban_sock: str = os.getenv("FAIL2BAN_SOCK", "/var/run/fail2ban/fail2ban.sock")
    log_file: str = os.getenv("FAIL2BAN_LOG", "/var/log/fail2ban.log")

settings = Settings()
Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)

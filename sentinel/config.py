from pydantic import BaseModel
import os
from pathlib import Path


class Settings(BaseModel):
    app_name: str = "SENTINEL PRO"
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8088"))
    secret_key: str = os.getenv("SECRET_KEY", "change-me")
    db_path: str = os.getenv("DB_PATH", "/data/sentinel.db")

    access_exp_minutes: int = int(os.getenv("ACCESS_EXP_MIN", "15"))
    refresh_exp_days: int = int(os.getenv("REFRESH_EXP_DAYS", "7"))
    max_failed_attempts: int = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
    lockout_minutes: int = int(os.getenv("LOCKOUT_MINUTES", "15"))

    fail2ban_sock: str = os.getenv("FAIL2BAN_SOCK", "/var/run/fail2ban/fail2ban.sock")
    log_file: str = os.getenv("FAIL2BAN_LOG", "/var/log/fail2ban.log")
    config_file: str = os.getenv("FAIL2BAN_CONFIG", "/etc/fail2ban/jail.local")
    config_backup_dir: str = os.getenv("CONFIG_BACKUP_DIR", "/data/config-backups")
    backup_keep: int = int(os.getenv("CONFIG_BACKUP_KEEP", "20"))


settings = Settings()
Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
Path(settings.config_backup_dir).mkdir(parents=True, exist_ok=True)

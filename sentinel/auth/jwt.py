import jwt
from datetime import datetime, timedelta, timezone
from sentinel.config import settings

ALGO = "HS256"

def create_access_token(sub: str):
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_exp_minutes)
    return jwt.encode({"sub": sub, "type": "access", "exp": exp}, settings.secret_key, algorithm=ALGO)

def create_refresh_token(sub: str):
    exp = datetime.now(timezone.utc) + timedelta(days=settings.refresh_exp_days)
    return jwt.encode({"sub": sub, "type": "refresh", "exp": exp}, settings.secret_key, algorithm=ALGO)

def decode_token(token: str):
    return jwt.decode(token, settings.secret_key, algorithms=[ALGO])

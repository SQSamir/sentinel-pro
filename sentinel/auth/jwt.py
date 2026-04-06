import jwt
import uuid
from datetime import datetime, timedelta, timezone
from sentinel.config import settings

ALGO = "HS256"


def create_access_token(sub: str, role: str):
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_exp_minutes)
    return jwt.encode({"sub": sub, "role": role, "type": "access", "exp": exp}, settings.secret_key, algorithm=ALGO)


def create_refresh_token(sub: str):
    exp = datetime.now(timezone.utc) + timedelta(days=settings.refresh_exp_days)
    jti = str(uuid.uuid4())
    token = jwt.encode({"sub": sub, "type": "refresh", "jti": jti, "exp": exp}, settings.secret_key, algorithm=ALGO)
    return token, jti, exp


def decode_token(token: str):
    return jwt.decode(token, settings.secret_key, algorithms=[ALGO])

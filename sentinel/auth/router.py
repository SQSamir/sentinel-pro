from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from sentinel.db import get_db, write_audit, fetchone, fetchall
from sentinel.config import settings
from .jwt import create_access_token, create_refresh_token, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginReq(BaseModel):
    username: str
    password: str


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="missing_token")
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="bad_token_type")
        username = payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

    db = await get_db()
    row = await fetchone(db, "SELECT id,username,role,disabled FROM users WHERE username=?", (username,))
    await db.close()
    if not row or row["disabled"]:
        raise HTTPException(status_code=401, detail="user_not_found")
    return dict(row)


@router.post("/login")
async def login(req: LoginReq, request: Request, response: Response):
    ip = request.client.host if request.client else ""
    db = await get_db()

    state = await fetchone(db, "SELECT failed_count,locked_until FROM login_attempts WHERE username=? AND ip=?", (req.username, ip))
    if state and state["locked_until"]:
        locked = await fetchone(db, "SELECT datetime('now') < datetime(?) as is_locked", (state["locked_until"],))
        if locked and locked["is_locked"]:
            await db.close()
            raise HTTPException(status_code=429, detail=f"locked_until:{state['locked_until']}")

    row = await fetchone(db, "SELECT id,username,password_hash,role,disabled FROM users WHERE username=?", (req.username,))
    ok = row and not row["disabled"] and pwd.verify(req.password, row["password_hash"])

    if not ok:
        await db.execute(
            """
            INSERT INTO login_attempts(username,ip,failed_count,updated_at)
            VALUES(?,?,1,CURRENT_TIMESTAMP)
            ON CONFLICT(username,ip) DO UPDATE SET
                failed_count=failed_count+1,
                updated_at=CURRENT_TIMESTAMP,
                locked_until=CASE WHEN failed_count+1 >= ? THEN datetime('now', ?) ELSE NULL END
            """,
            (req.username, ip, settings.max_failed_attempts, f"+{settings.lockout_minutes} minutes"),
        )
        await db.commit()
        await db.close()
        await write_audit(req.username, "login_failed", ip=ip)
        raise HTTPException(status_code=401, detail="invalid_credentials")

    await db.execute("DELETE FROM login_attempts WHERE username=? AND ip=?", (req.username, ip))

    access = create_access_token(row["username"], row["role"])
    refresh, jti, exp = create_refresh_token(row["username"])
    await db.execute(
        "INSERT INTO refresh_tokens(user_id,token_jti,ip,user_agent,expires_at) VALUES(?,?,?,?,?)",
        (row["id"], jti, ip, request.headers.get("user-agent", ""), exp.isoformat()),
    )
    await db.commit()
    await db.close()

    response.set_cookie("refresh_token", refresh, httponly=True, samesite="lax", secure=False, max_age=60 * 60 * 24 * settings.refresh_exp_days)
    await write_audit(row["username"], "login", ip=ip, detail=f"jti={jti}")
    return {"access_token": access, "token_type": "bearer", "role": row["role"]}


@router.post("/refresh")
async def refresh(request: Request, response: Response):
    rt = request.cookies.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=401, detail="missing_refresh")

    try:
        payload = decode_token(rt)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_refresh")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="bad_refresh_type")

    db = await get_db()
    user = await fetchone(db, "SELECT id,username,role,disabled FROM users WHERE username=?", (payload["sub"],))
    token = await fetchone(db, "SELECT id,revoked,expires_at FROM refresh_tokens WHERE token_jti=?", (payload.get("jti"),))
    if not user or user["disabled"] or not token or token["revoked"]:
        await db.close()
        raise HTTPException(status_code=401, detail="invalid_session")

    await db.execute("UPDATE refresh_tokens SET revoked=1 WHERE id=?", (token["id"],))
    new_refresh, new_jti, exp = create_refresh_token(user["username"])
    await db.execute(
        "INSERT INTO refresh_tokens(user_id,token_jti,ip,user_agent,expires_at) VALUES(?,?,?,?,?)",
        (user["id"], new_jti, request.client.host if request.client else "", request.headers.get("user-agent", ""), exp.isoformat()),
    )
    await db.commit()
    await db.close()

    response.set_cookie("refresh_token", new_refresh, httponly=True, samesite="lax", secure=False, max_age=60 * 60 * 24 * settings.refresh_exp_days)
    return {"access_token": create_access_token(user["username"], user["role"]), "token_type": "bearer"}


@router.post("/logout")
async def logout(request: Request, response: Response):
    rt = request.cookies.get("refresh_token")
    if rt:
        try:
            payload = decode_token(rt)
            db = await get_db()
            await db.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_jti=?", (payload.get("jti"),))
            await db.commit()
            await db.close()
        except Exception:
            pass
    response.delete_cookie("refresh_token")
    return {"ok": True}


@router.post("/logout-all")
async def logout_all(request: Request, user=Depends(get_current_user)):
    db = await get_db()
    await db.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (user["id"],))
    await db.commit()
    await db.close()
    await write_audit(user["username"], "logout_all", ip=request.client.host if request.client else "")
    return {"ok": True}


@router.get("/sessions")
async def sessions(user=Depends(get_current_user)):
    db = await get_db()
    rows = await fetchall(
        db,
        "SELECT id,ip,user_agent,created_at,expires_at,revoked FROM refresh_tokens WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (user["id"],),
    )
    await db.close()
    return [dict(r) for r in rows]


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user

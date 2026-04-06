from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from sentinel.db import get_db, write_audit, fetchone
from .jwt import create_access_token, create_refresh_token, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginReq(BaseModel):
    username: str
    password: str
    totp: str | None = None

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
    db = await get_db()
    row = await fetchone(db, "SELECT id,username,password_hash,role,disabled FROM users WHERE username=?", (req.username,))
    if not row or row["disabled"] or not pwd.verify(req.password, row["password_hash"]):
        await db.close()
        raise HTTPException(status_code=401, detail="invalid_credentials")
    access = create_access_token(row["username"])
    refresh = create_refresh_token(row["username"])
    await db.execute(
        "INSERT INTO refresh_tokens(user_id,token,ip,user_agent,expires_at) VALUES(?,?,?,?,datetime('now','+7 day'))",
        (row["id"], refresh, request.client.host if request.client else "", request.headers.get("user-agent", "")),
    )
    await db.commit()
    await db.close()
    response.set_cookie("refresh_token", refresh, httponly=True, samesite="lax", secure=False, max_age=60*60*24*7)
    await write_audit(row["username"], "login", ip=request.client.host if request.client else "")
    return {"access_token": access, "token_type": "bearer", "role": row["role"]}

@router.post("/refresh")
async def refresh(request: Request):
    rt = request.cookies.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=401, detail="missing_refresh")
    payload = decode_token(rt)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="bad_refresh_type")
    return {"access_token": create_access_token(payload["sub"]), "token_type": "bearer"}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"ok": True}

@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user

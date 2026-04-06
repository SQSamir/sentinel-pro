import asyncio
import json
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from passlib.context import CryptContext

from sentinel.config import settings
from sentinel.db import init_db, get_db, fetchone, fetchall
from sentinel.auth.router import router as auth_router, get_current_user
from sentinel.fail2ban.router import router as f2b_router
from sentinel.ws.manager import manager
from sentinel.auth.jwt import decode_token

app = FastAPI(title=settings.app_name)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router)
app.include_router(f2b_router)
app.mount("/static", StaticFiles(directory="sentinel/static"), name="static")
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.on_event("startup")
async def startup():
    await init_db()
    db = await get_db()
    cnt = await fetchone(db, "SELECT COUNT(*) c FROM users")
    if cnt["c"] == 0:
        admin_user = os.getenv("ADMIN_USERNAME", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin")
        await db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (admin_user, pwd.hash(admin_pass), "SUPERADMIN"))
        await db.commit()
    await db.close()


@app.get("/")
async def root():
    return FileResponse("sentinel/static/index.html")


@app.get("/system/health")
async def system_health(user=Depends(get_current_user)):
    db = await get_db()
    users = await fetchone(db, "SELECT COUNT(*) c FROM users")
    jails_ok = True
    await db.close()
    return {
        "status": "ok",
        "app": settings.app_name,
        "db": "ok",
        "users": users["c"],
        "log_file": settings.log_file,
        "jails_ok": jails_ok,
    }


@app.get("/audit")
async def audit(limit: int = 500, user=Depends(get_current_user)):
    db = await get_db()
    rows = await fetchall(db, "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    await db.close()
    return [dict(r) for r in rows]


@app.get("/audit/export")
async def audit_export(user=Depends(get_current_user)):
    db = await get_db()
    rows = await fetchall(db, "SELECT * FROM audit_log ORDER BY id DESC LIMIT 10000")
    await db.close()
    lines = [json.dumps(dict(r), ensure_ascii=False) for r in rows]
    return PlainTextResponse("\n".join(lines), media_type="application/x-ndjson")


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4401)
        return
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise ValueError("bad token")
    except Exception:
        await ws.close(code=4401)
        return

    await manager.connect(ws)

    async def tail_loop():
        pos = 0
        while True:
            try:
                with open(settings.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    await ws.send_json({"type": "log", "line": line})
            except FileNotFoundError:
                pass
            await asyncio.sleep(1)

    task = asyncio.create_task(tail_loop())
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        task.cancel()
        manager.disconnect(ws)

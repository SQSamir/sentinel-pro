from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sentinel.config import settings
from sentinel.db import init_db, get_db, fetchone, fetchall
import os
from sentinel.auth.router import router as auth_router, get_current_user
from sentinel.fail2ban.router import router as f2b_router
from sentinel.ws.manager import manager
from passlib.context import CryptContext

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
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        await db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (admin_user, pwd.hash(admin_pass), "SUPERADMIN"))
        await db.commit()
    await db.close()

@app.get("/")
async def root():
    return FileResponse("sentinel/static/index.html")

@app.get("/system/health")
async def system_health(user=Depends(get_current_user)):
    return {"status": "ok", "app": settings.app_name}

@app.get("/audit")
async def audit(user=Depends(get_current_user)):
    db = await get_db()
    rows = await fetchall(db, "SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")
    await db.close()
    return [dict(r) for r in rows]

@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            _ = await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)

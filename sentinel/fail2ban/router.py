from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from typing import Optional
import aiofiles
import os
import re
from datetime import datetime
from sentinel.auth.router import get_current_user
from sentinel.auth.rbac import require_role
from sentinel.db import get_db, fetchall, write_audit
from sentinel.config import settings
from .client import run_fail2ban
from .parser import analytics

router = APIRouter(prefix="/f2b", tags=["fail2ban"])


class BanReq(BaseModel):
    jail: str
    ip: str


class BulkReq(BaseModel):
    jail: str
    ips: list[str]


class WhitelistReq(BaseModel):
    entry: str
    note: str = ""


class ConfigReq(BaseModel):
    content: str


@router.get("/jails")
async def jails(user=Depends(get_current_user)):
    code, out, err = await run_fail2ban("status")
    if code != 0:
        raise HTTPException(status_code=500, detail=err or out)
    jails_list = []
    m = re.search(r"Jail list:\s*(.+)", out)
    if m:
        jails_list = [j.strip() for j in m.group(1).split(",") if j.strip()]
    return {"jails": jails_list, "raw": out}


@router.get("/jails/{jail}")
async def jail_detail(jail: str, user=Depends(get_current_user)):
    code, out, err = await run_fail2ban("status", jail)
    if code != 0:
        raise HTTPException(status_code=404, detail=err or out)
    return {"jail": jail, "raw": out}


@router.post("/jails/{jail}/start")
async def jail_start(jail: str, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    code, out, err = await run_fail2ban("start", jail)
    await write_audit(user["username"], "jail_start", target=jail)
    return {"code": code, "out": out, "err": err}


@router.post("/jails/{jail}/stop")
async def jail_stop(jail: str, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    code, out, err = await run_fail2ban("stop", jail)
    await write_audit(user["username"], "jail_stop", target=jail)
    return {"code": code, "out": out, "err": err}


@router.post("/reload")
async def reload_f2b(user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    code, out, err = await run_fail2ban("reload")
    await write_audit(user["username"], "reload")
    return {"code": code, "out": out, "err": err}


@router.post("/bans")
async def ban_ip(req: BanReq, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    code, out, err = await run_fail2ban("set", req.jail, "banip", req.ip)
    await write_audit(user["username"], "ban", target=f"{req.jail}:{req.ip}")
    return {"code": code, "out": out, "err": err}


@router.post("/bans/bulk")
async def ban_bulk(req: BulkReq, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    result = []
    for ip in req.ips:
        code, out, err = await run_fail2ban("set", req.jail, "banip", ip)
        result.append({"ip": ip, "code": code, "out": out, "err": err})
    await write_audit(user["username"], "ban_bulk", target=req.jail, detail=f"count={len(req.ips)}")
    return {"items": result}


@router.delete("/bans/{jail}/{ip}")
async def unban_ip(jail: str, ip: str, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    code, out, err = await run_fail2ban("set", jail, "unbanip", ip)
    await write_audit(user["username"], "unban", target=f"{jail}:{ip}")
    return {"code": code, "out": out, "err": err}


@router.post("/unban/bulk")
async def unban_bulk(req: BulkReq, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    result = []
    for ip in req.ips:
        code, out, err = await run_fail2ban("set", req.jail, "unbanip", ip)
        result.append({"ip": ip, "code": code, "out": out, "err": err})
    await write_audit(user["username"], "unban_bulk", target=req.jail, detail=f"count={len(req.ips)}")
    return {"items": result}


@router.get("/whitelist")
async def list_whitelist(user=Depends(get_current_user)):
    db = await get_db()
    rows = await fetchall(db, "SELECT * FROM whitelist ORDER BY id DESC")
    await db.close()
    return [dict(r) for r in rows]


@router.post("/whitelist")
async def add_whitelist(req: WhitelistReq, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    db = await get_db()
    await db.execute("INSERT OR IGNORE INTO whitelist(entry,note) VALUES(?,?)", (req.entry, req.note))
    await db.commit()
    await db.close()
    await write_audit(user["username"], "whitelist_add", target=req.entry)
    return {"ok": True}


@router.delete("/whitelist/{entry}")
async def del_whitelist(entry: str, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    db = await get_db()
    await db.execute("DELETE FROM whitelist WHERE entry=?", (entry,))
    await db.commit()
    await db.close()
    await write_audit(user["username"], "whitelist_del", target=entry)
    return {"ok": True}


@router.get("/config")
async def get_config(user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    if not os.path.exists(settings.config_file):
        return {"content": "", "path": settings.config_file}
    async with aiofiles.open(settings.config_file, "r") as f:
        return {"path": settings.config_file, "content": await f.read()}


@router.post("/config")
async def save_config(req: ConfigReq, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    # Minimal validation: ensure section header exists
    if "[" not in req.content or "]" not in req.content:
        raise HTTPException(status_code=400, detail="invalid_config_no_sections")

    os.makedirs(os.path.dirname(settings.config_file), exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup = os.path.join(settings.config_backup_dir, f"jail.local.{ts}.bak")

    if os.path.exists(settings.config_file):
        async with aiofiles.open(settings.config_file, "r") as src, aiofiles.open(backup, "w") as dst:
            await dst.write(await src.read())

    async with aiofiles.open(settings.config_file, "w") as f:
        await f.write(req.content)

    backups = sorted([p for p in os.listdir(settings.config_backup_dir) if p.startswith("jail.local.")])
    for old in backups[:-settings.backup_keep]:
        os.remove(os.path.join(settings.config_backup_dir, old))

    await write_audit(user["username"], "config_update", target=settings.config_file, detail=f"backup={backup}")
    return {"ok": True, "backup": backup}


@router.get("/logs")
async def get_logs(q: str = "", jail: Optional[str] = None, ip: Optional[str] = None, limit: int = 500, user=Depends(get_current_user)):
    try:
        async with aiofiles.open(settings.log_file, "r") as f:
            lines = await f.readlines()
    except FileNotFoundError:
        lines = []

    out = []
    for ln in lines[-50000:]:
        if q and q.lower() not in ln.lower():
            continue
        if jail and f"[{jail}]" not in ln:
            continue
        if ip and ip not in ln:
            continue
        out.append(ln.rstrip())
        if len(out) >= limit:
            break
    return {"items": out}


@router.get("/logs/export")
async def export_logs(user=Depends(get_current_user)):
    try:
        async with aiofiles.open(settings.log_file, "r") as f:
            data = await f.read()
    except FileNotFoundError:
        data = ""
    return PlainTextResponse(content=data, media_type="text/plain")


@router.get("/stats")
async def stats(user=Depends(get_current_user)):
    try:
        async with aiofiles.open(settings.log_file, "r") as f:
            lines = await f.readlines()
    except FileNotFoundError:
        lines = []
    return analytics(lines[-200000:])

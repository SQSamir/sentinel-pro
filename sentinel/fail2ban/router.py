from fastapi import APIRouter, Depends, HTTPException
from sentinel.auth.router import get_current_user
from sentinel.auth.rbac import require_role
from .client import run_fail2ban
from .parser import analytics
import aiofiles
from sentinel.config import settings

router = APIRouter(prefix="/f2b", tags=["fail2ban"])

@router.get("/jails")
async def jails(user=Depends(get_current_user)):
    code, out, err = await run_fail2ban("status")
    if code != 0:
        raise HTTPException(status_code=500, detail=err or out)
    return {"raw": out}

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
    return {"code": code, "out": out, "err": err}

@router.post("/jails/{jail}/stop")
async def jail_stop(jail: str, user=Depends(get_current_user)):
    require_role(user, "ADMIN")
    code, out, err = await run_fail2ban("stop", jail)
    return {"code": code, "out": out, "err": err}

@router.post("/bans")
async def ban_ip(payload: dict, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    jail = payload.get("jail")
    ip = payload.get("ip")
    if not jail or not ip:
        raise HTTPException(status_code=400, detail="jail and ip required")
    code, out, err = await run_fail2ban("set", jail, "banip", ip)
    return {"code": code, "out": out, "err": err}

@router.delete("/bans/{jail}/{ip}")
async def unban_ip(jail: str, ip: str, user=Depends(get_current_user)):
    require_role(user, "OPERATOR")
    code, out, err = await run_fail2ban("set", jail, "unbanip", ip)
    return {"code": code, "out": out, "err": err}

@router.get("/stats")
async def stats(user=Depends(get_current_user)):
    try:
        async with aiofiles.open(settings.log_file, "r") as f:
            lines = await f.readlines()
    except FileNotFoundError:
        lines = []
    return analytics(lines[-200000:])

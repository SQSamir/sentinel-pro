import asyncio
from asyncio.subprocess import PIPE

async def run_fail2ban(*args: str, timeout: int = 3):
    proc = await asyncio.create_subprocess_exec("fail2ban-client", *args, stdout=PIPE, stderr=PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

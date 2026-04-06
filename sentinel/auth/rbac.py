from fastapi import HTTPException

ROLE_LEVEL = {"VIEWER": 1, "OPERATOR": 2, "ADMIN": 3, "SUPERADMIN": 4}

def require_role(user: dict, minimum: str):
    if ROLE_LEVEL.get(user.get("role", "VIEWER"), 0) < ROLE_LEVEL[minimum]:
        raise HTTPException(status_code=403, detail="insufficient_permissions")

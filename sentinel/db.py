import aiosqlite
import hashlib
from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'SUPERADMIN',
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_jti TEXT UNIQUE NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  ip TEXT,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(username, ip)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  ip TEXT,
  detail TEXT,
  prev_hash TEXT,
  row_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry TEXT UNIQUE NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


async def get_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    return db


async def fetchone(db, query: str, params=()):
    cur = await db.execute(query, params)
    row = await cur.fetchone()
    await cur.close()
    return row


async def fetchall(db, query: str, params=()):
    cur = await db.execute(query, params)
    rows = await cur.fetchall()
    await cur.close()
    return rows


async def _table_columns(db, table: str):
    rows = await fetchall(db, f"PRAGMA table_info({table})")
    return {r['name'] for r in rows}


async def init_db():
    db = await get_db()
    await db.executescript(SCHEMA)

    # Lightweight migrations
    cols = await _table_columns(db, "refresh_tokens")
    if "token" in cols and "token_jti" not in cols:
        await db.execute("ALTER TABLE refresh_tokens RENAME COLUMN token TO token_jti")

    audit_cols = await _table_columns(db, "audit_log")
    if "prev_hash" not in audit_cols:
        await db.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if "row_hash" not in audit_cols:
        await db.execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT")

    await db.commit()
    await db.close()


async def write_audit(actor: str, action: str, target: str = "", ip: str = "", detail: str = ""):
    db = await get_db()
    prev = await fetchone(db, "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev_hash = (prev["row_hash"] if prev else "") or "GENESIS"
    raw = f"{prev_hash}|{actor}|{action}|{target}|{ip}|{detail}"
    row_hash = hashlib.sha256(raw.encode()).hexdigest()
    await db.execute(
        "INSERT INTO audit_log(actor,action,target,ip,detail,prev_hash,row_hash) VALUES(?,?,?,?,?,?,?)",
        (actor, action, target, ip, detail, prev_hash, row_hash),
    )
    await db.commit()
    await db.close()

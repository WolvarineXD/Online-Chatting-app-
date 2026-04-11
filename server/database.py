"""
SecureChat — Database Layer
============================
Tables:
  accounts  — permanent user credentials (auth_hash only, no plaintext)
  messages  — encrypted message blobs (server cannot decrypt)
  audit_log — metadata audit trail for legal / law-enforcement requests

IMPORTANT: The 'messages' table stores ONLY the encrypted ciphertext.
           Plaintext is never accessible to the server operator.
           The audit_log records *who* communicated and *when*, never *what*.
"""

import hashlib
import secrets
import time
from pathlib import Path
from typing import Optional

import aiosqlite

_DB: Optional[Path] = None


def init(db_path: Path) -> None:
    """Must be called once at startup before any DB operations."""
    global _DB
    _DB = db_path


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA
# ══════════════════════════════════════════════════════════════════════════════

async def setup() -> None:
    """Create all tables and indexes on first run."""
    async with aiosqlite.connect(_DB) as db:

        # Permanent user accounts
        await db.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                username   TEXT PRIMARY KEY,
                auth_hash  TEXT NOT NULL,   -- PBKDF2 of client-derived token
                auth_salt  TEXT NOT NULL,   -- random 32-byte salt (hex)
                created_at REAL NOT NULL DEFAULT 0,
                last_login REAL
            )
        """)

        # Encrypted message storage
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user  TEXT NOT NULL,
                to_user    TEXT NOT NULL,
                iv         TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                sent_at    REAL NOT NULL
            )
        """)

        # Audit log (metadata only — no message content)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL    NOT NULL,
                event      TEXT    NOT NULL,   -- 'join','leave','msg_sent','msg_recv'
                actor      TEXT    NOT NULL,   -- username
                peer       TEXT,               -- other party (for msg events)
                ip_hash    TEXT    NOT NULL,   -- one-way hashed IP
                detail     TEXT                -- optional extra info
            )
        """)

        # Indexes
        await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_to   ON messages(to_user,   sent_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_from ON messages(from_user, sent_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, ts)")
        await db.commit()


# ══════════════════════════════════════════════════════════════════════════════
# ACCOUNT AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def _hash_auth(auth_token: str, salt: bytes) -> str:
    """Server-side re-hash of the already-derived client auth token."""
    return hashlib.pbkdf2_hmac('sha256', auth_token.encode(), salt, 310_000).hex()


async def authenticate(username: str, auth_token: str) -> tuple[bool, str]:
    """
    Authenticate a user.

    - If the account does not exist: create it and return (True, 'created').
    - If it exists and credentials match: return (True, 'ok').
    - If credentials do not match: return (False, 'wrong_password').

    The auth_token is a client-derived hash of the account password; the
    server never sees the original plaintext password.
    """
    now = time.time()
    async with aiosqlite.connect(_DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT auth_hash, auth_salt FROM accounts WHERE username = ?", (username,)
        )
        row = await cur.fetchone()

        if row is None:
            # New account — hash the token with a fresh salt and store
            salt         = secrets.token_bytes(32)
            stored_hash  = _hash_auth(auth_token, salt)
            await db.execute(
                "INSERT INTO accounts (username, auth_hash, auth_salt, created_at) VALUES (?,?,?,?)",
                (username, stored_hash, salt.hex(), now),
            )
            await db.commit()
            return True, 'created'

        # Existing account — verify
        salt   = bytes.fromhex(row['auth_salt'])
        computed = _hash_auth(auth_token, salt)
        if secrets.compare_digest(computed, row['auth_hash']):
            await db.execute(
                "UPDATE accounts SET last_login = ? WHERE username = ?", (now, username)
            )
            await db.commit()
            return True, 'ok'

        return False, 'wrong_password'


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGES
# ══════════════════════════════════════════════════════════════════════════════

async def store_message(
    from_user: str, to_user: str, iv: str, ciphertext: str, ts: float
) -> int:
    async with aiosqlite.connect(_DB) as db:
        cur = await db.execute(
            "INSERT INTO messages (from_user, to_user, iv, ciphertext, sent_at) VALUES (?,?,?,?,?)",
            (from_user, to_user, iv, ciphertext, ts),
        )
        await db.commit()
        return cur.lastrowid  # type: ignore[return-value]


async def get_history(username: str, limit: int = 300) -> list[dict]:
    """Return the last *limit* messages involving *username*, oldest-first."""
    async with aiosqlite.connect(_DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT id, from_user, to_user, iv, ciphertext, sent_at
               FROM messages
               WHERE from_user = ? OR to_user = ?
               ORDER BY sent_at DESC LIMIT ?""",
            (username, username, limit),
        )
        rows = await cur.fetchall()
    return list(reversed([dict(r) for r in rows]))


async def purge_old_messages(ttl_days: int) -> int:
    """Delete messages older than *ttl_days*. Returns count deleted."""
    cutoff = time.time() - ttl_days * 86_400
    async with aiosqlite.connect(_DB) as db:
        cur = await db.execute("DELETE FROM messages WHERE sent_at < ?", (cutoff,))
        await db.commit()
        return cur.rowcount  # type: ignore[return-value]


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# Required for legal compliance. Records metadata only, never message content.
# Law enforcement may subpoena this log to determine who communicated and when.
# ══════════════════════════════════════════════════════════════════════════════

async def audit(event: str, actor: str, ip_hash: str,
                peer: str = '', detail: str = '') -> None:
    """
    Append an immutable audit record.

    Events:
      join       — user connected and authenticated
      leave      — user disconnected
      msg_sent   — user sent an encrypted message (peer = recipient)
      msg_recv   — message delivered to online recipient
      auth_fail  — failed authentication attempt
      new_acct   — new account created
    """
    async with aiosqlite.connect(_DB) as db:
        await db.execute(
            "INSERT INTO audit_log (ts, event, actor, peer, ip_hash, detail) "
            "VALUES (?,?,?,?,?,?)",
            (time.time(), event, actor, peer or '', ip_hash, detail or ''),
        )
        await db.commit()

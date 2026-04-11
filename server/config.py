"""
SecureChat — Server Configuration
===================================
All settings can be overridden via environment variables.
Copy .env.example to .env and set values there.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent


class Config:
    # ── Server ──────────────────────────────────────────────────────────────
    HOST: str  = os.getenv("HOST", "0.0.0.0")
    PORT: int  = int(os.getenv("PORT", "8080"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ── Paths ────────────────────────────────────────────────────────────────
    STATIC_DIR: Path = BASE_DIR / "static"
    DB_FILE:    Path = BASE_DIR / os.getenv("DB_FILE",  "chat.db")
    LOG_FILE:   Path = BASE_DIR / os.getenv("LOG_FILE", "logs/server.log")

    # ── Database ─────────────────────────────────────────────────────────────
    MSG_HISTORY_LIMIT: int = int(os.getenv("MSG_HISTORY_LIMIT", "300"))
    MSG_TTL_DAYS:      int = int(os.getenv("MSG_TTL_DAYS",      "30"))

    # ── Security / Rate-limiting ──────────────────────────────────────────────
    # Maximum ciphertext characters per message (AES base64 ≈ 4/3 of plaintext)
    MAX_MSG_LENGTH:         int   = int(os.getenv("MAX_MSG_LENGTH",         "4096"))
    MAX_CONNECTIONS_PER_IP: int   = int(os.getenv("MAX_CONNECTIONS_PER_IP", "5"))
    MAX_TOTAL_CONNECTIONS:  int   = int(os.getenv("MAX_TOTAL_CONNECTIONS",  "200"))
    RATE_LIMIT_MSGS:        int   = int(os.getenv("RATE_LIMIT_MSGS",        "30"))  # per window
    RATE_LIMIT_WINDOW:      float = float(os.getenv("RATE_LIMIT_WINDOW",    "60"))  # seconds
    WS_HANDSHAKE_TIMEOUT:   float = float(os.getenv("WS_HANDSHAKE_TIMEOUT", "15"))

    # ── Username rules ────────────────────────────────────────────────────────
    USERNAME_MIN_LEN: int = 2
    USERNAME_MAX_LEN: int = 30

    # Names that could be used for impersonation / abuse
    RESERVED_USERNAMES: frozenset = frozenset({
        "admin", "administrator", "system", "server", "bot",
        "securechat", "support", "moderator", "mod", "root",
        "null", "undefined", "anonymous", "guest", "helpdesk",
    })

    # ── HTTP Security Headers ─────────────────────────────────────────────────
    SECURITY_HEADERS: dict = {
        "X-Content-Type-Options":  "nosniff",
        "X-Frame-Options":         "DENY",
        "X-XSS-Protection":        "1; mode=block",
        "Referrer-Policy":         "strict-origin-when-cross-origin",
        "Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' wss: ws:; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        ),
    }

"""
SecureChat — Security Layer  (security.py)
==========================================
Defence layers:
  1. AuthRateLimiter  — per-username + per-IP brute-force lockout
  2. ReplayGuard      — nonce-based message replay prevention
  3. ConnectionLimiter— per-IP and global connection caps
  4. MessageRateLimiter (sliding window)
  5. Validator        — strict field sanitisation / size enforcement
"""

import hashlib
import re
import time
from collections import defaultdict, deque
from typing import Optional

from .config import Config

# ─────────────────────────────────────────────────────────────────────────────
# IP helpers
# ─────────────────────────────────────────────────────────────────────────────

def ip_hash(ip: str) -> str:
    """One-way SHA-256 hash of raw IP — never log the cleartext address."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Auth brute-force lockout (Layer 1)
# ─────────────────────────────────────────────────────────────────────────────

class AuthRateLimiter:
    """
    Tracks authentication failures per (username, ip_hash) pair.

    Thresholds (applied within a 10-minute window):
        ≥ 5  failures → 15-minute lockout
        ≥ 10 failures → 1-hour  hard lockout
        ≥ 20 failures → IP permanently banned for this session
    """
    WINDOW_SECS    = 600   # 10 min tracking window
    SOFT_THRESHOLD = 5
    SOFT_LOCKOUT   = 900   # 15 min
    HARD_THRESHOLD = 10
    HARD_LOCKOUT   = 3600  # 1 hour
    BAN_THRESHOLD  = 20

    def __init__(self):
        # key: "username:ip_hash" → list of failure timestamps
        self._failures: dict[str, list[float]] = defaultdict(list)
        # key: "username:ip_hash" → unlock-at monotonic timestamp
        self._locked: dict[str, float] = {}
        # ip_hashes that should be banned (relayed to ConnectionLimiter)
        self.pending_bans: set[str] = set()

    def is_allowed(self, username: str, ip_h: str) -> tuple[bool, Optional[str]]:
        """
        Call BEFORE calling db.authenticate().
        Returns (allowed: bool, reason: str | None).
        """
        key = f"{username}:{ip_h}"
        now = time.monotonic()

        if key in self._locked:
            until = self._locked[key]
            if now < until:
                wait = int(until - now)
                mins = wait // 60
                secs = wait % 60
                t    = f"{mins}m {secs}s" if mins else f"{secs}s"
                return False, f"Too many failed attempts. Try again in {t}."
            # Lockout expired — clear it
            del self._locked[key]
            self._failures[key] = []

        return True, None

    def record_failure(self, username: str, ip_h: str) -> None:
        key = f"{username}:{ip_h}"
        now = time.monotonic()
        # Keep only failures within the tracking window
        self._failures[key] = [
            t for t in self._failures[key] if now - t < self.WINDOW_SECS
        ]
        self._failures[key].append(now)
        n = len(self._failures[key])

        if n >= self.BAN_THRESHOLD:
            self.pending_bans.add(ip_h)
            self._locked[key] = now + self.HARD_LOCKOUT
        elif n >= self.HARD_THRESHOLD:
            self._locked[key] = now + self.HARD_LOCKOUT
        elif n >= self.SOFT_THRESHOLD:
            self._locked[key] = now + self.SOFT_LOCKOUT

    def record_success(self, username: str, ip_h: str) -> None:
        """Clear failure history on successful authentication."""
        key = f"{username}:{ip_h}"
        self._failures.pop(key, None)
        self._locked.pop(key, None)

    def drain_bans(self) -> set[str]:
        """Return and clear any IPs queued for banning."""
        b = set(self.pending_bans)
        self.pending_bans.clear()
        return b


auth_limiter = AuthRateLimiter()


# ─────────────────────────────────────────────────────────────────────────────
# Replay guard (Layer 2)
# ─────────────────────────────────────────────────────────────────────────────

class ReplayGuard:
    """
    Prevents message replay attacks.
    Each message must carry a unique nonce; nonces are remembered for TTL seconds.
    Timestamps are also checked — messages > SKEW_SECS old or in the future are rejected.
    """
    TTL      = 300  # 5 minutes — nonce retention
    SKEW_SECS = 300 # Max allowed timestamp difference (client vs server)

    def __init__(self):
        self._seen: dict[str, float] = {}   # nonce → inserted_at

    def _evict(self) -> None:
        now = time.monotonic()
        self._seen = {k: v for k, v in self._seen.items() if now - v < self.TTL}

    def is_fresh(self, nonce: Optional[str], client_ts: Optional[float]) -> tuple[bool, str]:
        """
        Returns (ok, reason).
        Call once per incoming message packet.
        """
        # --- Timestamp check ------------------------------------------------
        if client_ts is not None:
            skew = abs(time.time() - float(client_ts))
            if skew > self.SKEW_SECS:
                return False, "Message timestamp is too old or too far in the future."

        # --- Nonce uniqueness -----------------------------------------------
        if nonce:
            self._evict()
            if nonce in self._seen:
                return False, "Duplicate message (replay detected)."
            self._seen[nonce] = time.monotonic()

        return True, ""


replay_guard = ReplayGuard()


# ─────────────────────────────────────────────────────────────────────────────
# Connection limiter (Layer 3)
# ─────────────────────────────────────────────────────────────────────────────

_ip_conns:   dict[str, int] = defaultdict(int)
_banned_ips: set[str]       = set()
_total: int = 0

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-\. ]+$")


def ip_connect(h: str) -> bool:
    if h in _banned_ips:
        return False
    if _ip_conns[h] >= Config.MAX_CONNECTIONS_PER_IP:
        return False
    _ip_conns[h] += 1
    return True


def ip_disconnect(h: str) -> None:
    if _ip_conns[h] > 0:
        _ip_conns[h] -= 1


def ban_ip(h: str) -> None:
    _banned_ips.add(h)


def total_connect() -> bool:
    global _total
    if _total >= Config.MAX_TOTAL_CONNECTIONS:
        return False
    _total += 1
    return True


def total_disconnect() -> None:
    global _total
    if _total > 0:
        _total -= 1


def active_count() -> int:
    return _total


# ─────────────────────────────────────────────────────────────────────────────
# Field validation (Layer 4)
# ─────────────────────────────────────────────────────────────────────────────

def validate_username(name: str) -> Optional[str]:
    if not name or not isinstance(name, str):
        return "Username is required."
    name = name.strip()
    if len(name) < Config.USERNAME_MIN_LEN:
        return f"Username must be at least {Config.USERNAME_MIN_LEN} characters."
    if len(name) > Config.USERNAME_MAX_LEN:
        return f"Username must be at most {Config.USERNAME_MAX_LEN} characters."
    if not _USERNAME_RE.match(name):
        return "Username may only contain letters, numbers, spaces, dots, hyphens, underscores."
    if name.lower() in Config.RESERVED_USERNAMES:
        return f"'{name}' is a reserved name. Please choose another."
    return None


def validate_message(pkt: dict) -> Optional[str]:
    """
    Structural validation only — server cannot read encrypted content.
    """
    iv         = pkt.get("iv", "")
    ct         = pkt.get("ciphertext", "")
    to         = pkt.get("to", "")

    if not iv or not ct or not to:
        return "Malformed message: missing iv, ciphertext, or to."

    # ~4/3 expansion for base64 + AES block padding
    if len(ct) > Config.MAX_MSG_LENGTH * 4:
        return "Message payload too large."

    if not isinstance(to, str) or len(to) > Config.USERNAME_MAX_LEN:
        return "Invalid recipient."

    # Auth token length sanity (should be 64-char hex from PBKDF2)
    return None


def validate_auth_token(token: str) -> Optional[str]:
    """Reject tokens that could not possibly be a PBKDF2 hex digest."""
    if not token or not isinstance(token, str):
        return "auth_token is required."
    token = token.strip()
    if len(token) < 32:
        return "auth_token is too short."
    if len(token) > 256:
        return "auth_token is too long."
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Message rate limiter — sliding window (Layer 5)
# ─────────────────────────────────────────────────────────────────────────────

_rate_data: dict[str, deque] = defaultdict(deque)


def check_rate_limit(username: str) -> bool:
    """
    Return True if within Config.RATE_LIMIT_MSGS / Config.RATE_LIMIT_WINDOW.
    """
    now    = time.monotonic()
    cutoff = now - Config.RATE_LIMIT_WINDOW
    dq     = _rate_data[username]

    while dq and dq[0] < cutoff:
        dq.popleft()

    if len(dq) >= Config.RATE_LIMIT_MSGS:
        return False

    dq.append(now)
    return True

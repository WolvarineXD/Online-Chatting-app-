"""
SecureChat — WebSocket Relay + HTTP Routes
==========================================
Protocol:

  Client → Server:
    { type:"hello",   username, auth_token }           ← login/register
    { type:"message", to, iv, ciphertext }             ← encrypted DM (stored)
    { type:"typing",  to }                             ← ephemeral, not stored
    { type:"read",    to, id }                         ← ephemeral, not stored

  Server → Client:
    { type:"welcome",   new_account: bool }            ← auth successful
    { type:"user_list", users: [...] }                 ← roster update
    { type:"history",   messages: [...] }              ← on login
    { type:"message",   from, to, iv, ciphertext, ts, id }
    { type:"typing",    from }
    { type:"read",      from, id }
    { type:"error",     message }                      ← auth fail, etc.

Security: The server NEVER decrypts messages. Only the iv + ciphertext blob
          is stored and relayed. All audit metadata is persisted for compliance.
"""

import asyncio
import json
import logging
import time

import aiohttp
from aiohttp import web

from . import database as db
from . import security
from .config import Config

log = logging.getLogger("relay")

# Live sessions: username → WebSocketResponse
online: dict[str, web.WebSocketResponse] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _send(ws: web.WebSocketResponse, obj: dict) -> bool:
    try:
        await ws.send_json(obj)
        return True
    except Exception:
        return False


async def _broadcast_user_list() -> None:
    roster = {"type": "user_list", "users": list(online.keys())}
    dead: list[str] = []
    for uname, ws in list(online.items()):
        if not await _send(ws, roster):
            dead.append(uname)
    for u in dead:
        online.pop(u, None)


# ── Security middleware ────────────────────────────────────────────────────────

@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    response = await handler(request)
    for key, value in Config.SECURITY_HEADERS.items():
        response.headers[key] = value
    return response


# ── WebSocket handler ─────────────────────────────────────────────────────────

async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    peername  = request.transport.get_extra_info("peername") or ("0.0.0.0", 0)
    client_ip = peername[0]
    ih        = security.ip_hash(client_ip)

    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    # ── Global and per-IP connection caps ─────────────────────────────────────
    if not security.total_connect():
        await _send(ws, {"type": "error", "message": "Server at capacity. Try again later."})
        await ws.close()
        return ws

    if not security.ip_connect(ih):
        await _send(ws, {"type": "error",
                         "message": "Too many connections from your network."})
        security.total_disconnect()
        await ws.close()
        return ws

    username: str | None = None

    try:
        # ── Handshake ─────────────────────────────────────────────────────────
        try:
            frame = await asyncio.wait_for(ws.receive(), timeout=Config.WS_HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("Handshake timeout  ip=%s", ih)
            await ws.close()
            return ws

        if frame.type != aiohttp.WSMsgType.TEXT:
            await ws.close()
            return ws

        try:
            pkt = json.loads(frame.data)
        except json.JSONDecodeError:
            await _send(ws, {"type": "error", "message": "Invalid JSON."})
            await ws.close()
            return ws

        if pkt.get("type") != "hello":
            await _send(ws, {"type": "error", "message": "Expected 'hello'."})
            await ws.close()
            return ws

        username   = str(pkt.get("username", "")).strip()
        auth_token = str(pkt.get("auth_token", "")).strip()

        # ── Validate username format ──────────────────────────────────────────
        err = security.validate_username(username)
        if err:
            await _send(ws, {"type": "error", "message": err})
            await ws.close()
            return ws

        # ── Validate auth token format ────────────────────────────────────────
        token_err = security.validate_auth_token(auth_token)
        if token_err:
            await _send(ws, {"type": "error", "message": token_err})
            await ws.close()
            return ws

        # ── Brute-force lockout check (BEFORE hitting the database) ───────────
        allowed, lockout_msg = security.auth_limiter.is_allowed(username, ih)
        if not allowed:
            await db.audit("auth_blocked", username, ih, detail="lockout")
            await _send(ws, {"type": "error", "message": lockout_msg})
            log.warning("BLOCKED    %-20s  ip=%s  (lockout)", f"'{username}'", ih)
            await ws.close()
            return ws

        # ── Authenticate / create account ──────────────────────────────────────
        ok, reason = await db.authenticate(username, auth_token)

        if not ok:
            security.auth_limiter.record_failure(username, ih)
            # Ban IPs that crossed the abuse threshold
            for bad_ip in security.auth_limiter.drain_bans():
                security.ban_ip(bad_ip)
                log.warning("BAN        ip=%s  (auth abuse)", bad_ip)
            await db.audit("auth_fail", username, ih, detail=reason)
            await _send(ws, {"type": "error",
                             "message": (
                                 f"Wrong Account Password for '{username}'. "
                                 "Your account already exists — use the exact same "
                                 "password you registered with."
                             )})
            log.warning("AUTH FAIL  %-20s  ip=%s", f"'{username}'", ih)
            await ws.close()
            return ws

        # ── Auth succeeded — clear failure history ────────────────────────────
        security.auth_limiter.record_success(username, ih)

        # Check if already connected
        if username in online:
            await _send(ws, {"type": "error",
                             "message": f"'{username}' is already online. "
                                        "Open a new session to reconnect."})
            await ws.close()
            return ws

        new_account = (reason == 'created')
        if new_account:
            await db.audit("new_acct", username, ih)
            log.info("NEW   %-20s  ip=%s", f"'{username}'", ih)
        else:
            log.info("JOIN  %-20s  ip=%s  |  online: %d", f"'{username}'", ih, len(online) + 1)

        await db.audit("join", username, ih)

        # ── Register ──────────────────────────────────────────────────────────
        online[username] = ws
        await _send(ws, {"type": "welcome", "new_account": new_account})

        # ── History ───────────────────────────────────────────────────────────
        history = await db.get_history(username, Config.MSG_HISTORY_LIMIT)
        if history:
            await _send(ws, {"type": "history", "messages": history})

        # ── Broadcast roster ──────────────────────────────────────────────────
        await _broadcast_user_list()

        # ── Relay loop ────────────────────────────────────────────────────────
        async for frame in ws:
            if frame.type == aiohttp.WSMsgType.TEXT:
                try:
                    msg = json.loads(frame.data)
                except json.JSONDecodeError:
                    continue

                mtype = msg.get("type")

                # Chat message (persisted + relayed) ─────────────────────────
                if mtype == "message":
                    merr = security.validate_message(msg)
                    if merr:
                        await _send(ws, {"type": "error", "message": merr})
                        continue

                    # ── Replay guard (nonce + timestamp check) ────────────────
                    nonce     = str(msg.get("nonce", "")) or None
                    client_ts = msg.get("ts")
                    fresh, fresh_reason = security.replay_guard.is_fresh(nonce, client_ts)
                    if not fresh:
                        log.warning("REPLAY     user='%s'  reason=%s", username, fresh_reason)
                        await _send(ws, {"type": "error", "message": "Message rejected: " + fresh_reason})
                        continue

                    if not security.check_rate_limit(username):
                        await _send(ws, {"type": "error",
                                         "message": "Slow down — too many messages."})
                        continue

                    target     = str(msg.get("to", ""))
                    iv         = str(msg.get("iv", ""))
                    ciphertext = str(msg.get("ciphertext", ""))
                    ts         = time.time()

                    msg_id = await db.store_message(username, target, iv, ciphertext, ts)

                    # Audit (metadata only — no content)
                    await db.audit("msg_sent", username, ih, peer=target,
                                   detail=f"id={msg_id}")

                    relay_pkt = {
                        "type": "message", "from": username, "to": target,
                        "iv": iv, "ciphertext": ciphertext, "ts": ts, "id": msg_id,
                    }

                    if target in online:
                        await _send(online[target], relay_pkt)
                        await db.audit("msg_recv", target, ih, peer=username,
                                       detail=f"id={msg_id}")
                        log.info("MSG   %-15s → %-15s  id=%d",
                                 f"'{username}'", f"'{target}'", msg_id)
                    else:
                        log.info("STORE %-15s → %-15s  id=%d (offline)",
                                 f"'{username}'", f"'{target}'", msg_id)

                # Typing indicator (ephemeral) ────────────────────────────────
                elif mtype == "typing":
                    t = str(msg.get("to", ""))
                    if t in online:
                        await _send(online[t], {"type": "typing", "from": username})

                # Read receipt (ephemeral) ────────────────────────────────────
                elif mtype == "read":
                    t = str(msg.get("to", ""))
                    if t in online:
                        await _send(online[t], {"type": "read",
                                                "from": username, "id": msg.get("id")})

            elif frame.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break

    except Exception as exc:
        log.error("ERROR  user='%s': %s", username or "?", exc, exc_info=Config.DEBUG)

    finally:
        security.ip_disconnect(ih)
        security.total_disconnect()
        if username:
            online.pop(username, None)
            await db.audit("leave", username, ih)
            log.info("LEAVE %-20s  |  online: %d", f"'{username}'", len(online))
            await _broadcast_user_list()

    return ws


# ── HTTP routes ───────────────────────────────────────────────────────────────

async def index_handler(request: web.Request) -> web.FileResponse:
    index = Config.STATIC_DIR / "index.html"
    if not index.exists():
        raise web.HTTPNotFound(text="index.html not found. Check STATIC_DIR.")
    return web.FileResponse(index, headers={"Cache-Control": "no-cache"})


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "status": "ok",
        "online_users": len(online),
        "version": "2.0.0",
    })


# ── Background tasks ──────────────────────────────────────────────────────────

async def purge_task(ttl_days: int) -> None:
    while True:
        await asyncio.sleep(86_400)
        n = await db.purge_old_messages(ttl_days)
        if n:
            log.info("PURGE  Removed %d messages older than %d days.", n, ttl_days)

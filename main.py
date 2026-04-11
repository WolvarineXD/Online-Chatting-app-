"""
SecureChat — Entry Point
=========================
Usage:
    python main.py

For internet access:
    1. Start server:  python main.py
    2. Open tunnel:   ngrok http 8080
    3. Share the https://xxxxx.ngrok-free.app URL with friends.

MIT License | Use responsibly | See README.md
"""

import asyncio
import logging
import socket
from logging.handlers import RotatingFileHandler

from aiohttp import web

from server import database as db
from server import relay
from server.config import Config


def _setup_logging() -> None:
    Config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "[%(asctime)s]  %(levelname)-5s  %(name)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)

    fh = RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    fh.setLevel(logging.INFO)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if Config.DEBUG else logging.INFO)
    root.addHandler(console)
    root.addHandler(fh)


async def create_app() -> web.Application:
    db.init(Config.DB_FILE)
    await db.setup()

    app = web.Application(middlewares=[relay.security_headers_middleware])

    # Routes
    app.router.add_get("/",       relay.index_handler)
    app.router.add_get("/health", relay.health_handler)
    app.router.add_get("/ws",     relay.ws_handler)
    app.router.add_static("/static", Config.STATIC_DIR, show_index=False)

    # Background task: daily message purge
    async def _start_purge(_app: web.Application) -> None:
        asyncio.create_task(relay.purge_task(Config.MSG_TTL_DAYS))

    app.on_startup.append(_start_purge)
    return app


def _banner(local_ip: str) -> None:
    log = logging.getLogger("main")
    lines = [
        "╔══════════════════════════════════════════════════════════╗",
        "║         SecureChat  v2.0  —  E2EE Relay + DB             ║",
        "╠══════════════════════════════════════════════════════════╣",
        f"║  Local      →  http://localhost:{Config.PORT}                     ║",
        f"║  LAN        →  http://{local_ip}:{Config.PORT}",
        f"║  Internet   →  ngrok http {Config.PORT}   (then share the URL)   ║",
        "╠══════════════════════════════════════════════════════════╣",
        f"║  Database   →  {Config.DB_FILE}",
        f"║  Logs       →  {Config.LOG_FILE}",
        f"║  Health     →  http://localhost:{Config.PORT}/health",
        "╚══════════════════════════════════════════════════════════╝",
    ]
    for line in lines:
        log.info(line)


def main() -> None:
    _setup_logging()

    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "your-pc-ip"

    _banner(local_ip)

    web.run_app(
        create_app(),
        host=Config.HOST,
        port=Config.PORT,
        access_log=None,
        print=lambda *_: None,  # suppress aiohttp's default startup message
    )


if __name__ == "__main__":
    main()

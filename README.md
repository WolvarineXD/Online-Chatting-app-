# SecureChat v2

**Production-ready, end-to-end encrypted private messaging with permanent accounts and compliance logging.**

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
python main.py

# 3. Open in browser
#    Local:    http://localhost:8080
#    LAN:      http://<your-ip>:8080
#    Internet: start ngrok (see below)
```

---

## Internet Access (ngrok)

```bash
# In a second terminal (keep server running in first)
ngrok http 8080
```

Share the `https://xxxx.ngrok-free.app` URL with friends. The app automatically detects whether it's running over HTTP or HTTPS and uses `ws://` or `wss://` accordingly.

---

## How It Works

### Permanent Accounts
- Your **username + account password** creates a persistent account on first login.
- Subsequent logins with the same credentials restore your conversation history.
- The account password is **never sent to the server** — a PBKDF2 derived token is sent instead. The server re-hashes it with a random per-user salt before storing.

### End-to-End Encryption
- The **Chat Password** is entirely separate from the account password.
- It is used client-side to derive an AES-256 key unique to each pair of users.
- **The server never sees the chat password or message plaintext.**
- Everyone you want to chat with privately must use the same Chat Password.

### What the Server Stores

| Data | Stored |
|------|--------|
| Message plaintext | ❌ Never |
| Account password | ❌ Never (derived token stored, re-hashed) |
| Chat password | ❌ Never |
| Encrypted message blobs | ✅ Yes (can't decrypt without Chat Password) |
| Message metadata (who→whom, when) | ✅ Yes (audit_log table) |
| Connection events with IP hash | ✅ Yes (audit_log table) |
| Account creation/last login time | ✅ Yes (accounts table) |

---

## Security Features

| Threat | Mitigation |
|--------|-----------|
| Spam / flood attacks | Sliding-window rate limiter (30 msg/60 s per user) |
| DoS via connections | 5 connections per IP, 200 total |
| Impersonation | Reserved username blocklist, account passwords |
| XSS | All message text HTML-escaped on render |
| Malformed packets | Strict JSON validation, field size limits |
| Data retention | Messages auto-purged after 30 days (configurable) |
| HTTP attacks | Full security header set (CSP, X-Frame-Options, etc.) |
| Weak passwords | Client-side strength meter, server minimum enforced |

---

## Law Enforcement / Legal Compliance

The **audit_log** table in `chat.db` records:
- Account creation and login events
- Connection and disconnection events
- Message routing metadata (sender, recipient, timestamp, message ID)
- Hashed (one-way) network addresses

This data can be provided to law enforcement under a valid legal order.  
**Message content cannot be provided** — it is encrypted client-side and the server does not hold decryption keys.

---

## File Structure

```
chatting/
├── main.py                  ← Entry point  (python main.py)
├── requirements.txt
├── README.md
├── .env.example             ← Copy to .env to configure
├── chat.db                  ← Created automatically on first run
├── logs/
│   └── server.log           ← Rotating log file
├── server/
│   ├── config.py            ← All server configuration
│   ├── database.py          ← SQLite: accounts, messages, audit_log
│   ├── security.py          ← Rate limiting, IP tracking, validation
│   └── relay.py             ← WebSocket handler + HTTP routes
└── static/
    ├── index.html           ← App shell
    ├── css/styles.css       ← All styling
    └── js/
        ├── crypto.js        ← AES-256 + auth token derivation
        ├── ui.js            ← DOM rendering
        ├── network.js       ← WebSocket connection
        └── app.js           ← Main app logic
```

---

## Configuration

Copy `.env.example` to `.env` and edit values. All settings can also be set as environment variables.

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `MSG_TTL_DAYS` | `30` | Days before messages are purged |
| `RATE_LIMIT_MSGS` | `30` | Max messages per 60-second window |
| `MAX_CONNECTIONS_PER_IP` | `5` | Max simultaneous connections per IP |
| `MAX_TOTAL_CONNECTIONS` | `200` | Server-wide connection cap |

---

## Health Check

```
GET http://localhost:8080/health
```
Returns: `{"status": "ok", "online_users": N, "version": "2.0.0"}`

---

## License

MIT. Use responsibly. The operator of this server is responsible for compliance with applicable laws.

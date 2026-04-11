/**
 * SecureChat — Network Module (network.js)
 * ==========================================
 * Manages the WebSocket connection lifecycle:
 *   - Handshake (hello + auth_token packet)
 *   - Incoming packet routing to App handlers
 *   - Outgoing helpers (sendMessage, sendTyping, sendRead)
 *   - Auto-reconnect with exponential back-off
 */

const Network = (() => {
  let _ws      = null;
  let _alive   = false;
  let _retries = 0;
  let _authToken = '';
  const MAX_RETRIES = 6;

  // ── Connect ────────────────────────────────────────────────────────────────

  /**
   * @param {string} username
   * @param {string} authToken  — client-derived hash of account password
   */
  function connect(username, authToken) {
    _alive     = true;
    _authToken = authToken || '';
    _open(username);
  }

  function _open(username) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url   = `${proto}//${window.location.host}/ws`;

    _ws = new WebSocket(url);

    _ws.onopen = () => {
      _retries = 0;
      _ws.send(JSON.stringify({ type: 'hello', username, auth_token: _authToken }));
    };

    _ws.onmessage = (e) => {
      let pkt;
      try { pkt = JSON.parse(e.data); } catch { return; }
      _route(pkt);
    };

    _ws.onerror = () => {
      // onerror fires before onclose — use it to detect initial connection failure
      if (_retries === 0) {
        App.onServerError('Cannot connect to server. Make sure the server is running.');
        _alive = false; // stop auto-reconnect on login failure
      }
    };

    _ws.onclose = () => {
      _ws = null;
      App.onDisconnected();
      if (_alive && _retries < MAX_RETRIES) {
        const delay = Math.min(1000 * 2 ** _retries, 30_000);
        _retries++;
        UI.showToast(`Connection lost. Reconnecting in ${Math.round(delay / 1000)}s…`);
        setTimeout(() => { if (_alive) _open(username); }, delay);
      }
    };
  }

  function disconnect() {
    _alive = false;
    if (_ws) { _ws.close(); _ws = null; }
  }

  // ── Packet routing ────────────────────────────────────────────────────────

  function _route(pkt) {
    switch (pkt.type) {
      case 'welcome':   App.onWelcome(pkt);                break;
      case 'user_list': App.onUserList(pkt.users);         break;
      case 'history':   App.onHistory(pkt.messages);       break;
      case 'message':   App.onMessage(pkt);                break;
      case 'typing':    App.onTyping(pkt.from);            break;
      case 'read':      App.onRead(pkt.from, pkt.id);      break;
      case 'error':     App.onServerError(pkt.message);    break;
      default:          /* unknown packet type — ignore */  break;
    }
  }

  // ── Send helpers ──────────────────────────────────────────────────────────

  function _send(obj) {
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  function sendMessage(to, iv, ciphertext) {
    // nonce + ts used by server-side ReplayGuard to reject duplicates
    const nonce = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    const ts = Date.now() / 1000;   // Unix epoch (seconds, matches server time.time())
    return _send({ type: 'message', to, iv, ciphertext, nonce, ts });
  }

  // Throttled: send at most one typing packet per 2 seconds
  let _typingThrottle = 0;
  function sendTyping(to) {
    const now = Date.now();
    if (now - _typingThrottle < 2000) return;
    _typingThrottle = now;
    _send({ type: 'typing', to });
  }

  function sendRead(to, id) {
    _send({ type: 'read', to, id });
  }

  function isConnected() {
    return _ws !== null && _ws.readyState === WebSocket.OPEN;
  }

  return { connect, disconnect, sendMessage, sendTyping, sendRead, isConnected };
})();

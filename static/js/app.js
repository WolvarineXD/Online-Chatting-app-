/**
 * SecureChat — App Controller  (app.js)
 * =======================================
 * Central state, login flow, and event wiring.
 * All DOM events are bound here via addEventListener — no inline handlers.
 *
 * Load order: crypto.js → ui.js → network.js → app.js
 */

const App = (() => {

  // ── Shared state ───────────────────────────────────────────────
  const state = {
    me:           null,   // logged-in username
    chatPassword: null,   // shared E2EE password (NEVER sent to server)
    keyCache:     {},     // { peer: CryptoJS derived key }
    chats:        {},     // { peer: [{ id, from, text, ts, mine }] }
    unread:       {},     // { peer: count }
    online:       new Set(),
    active:       null,   // open chat peer
  };

  // ── Helpers ────────────────────────────────────────────────────
  function _uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2); }

  // ══════════════════════════════════════════════════════════════
  // LOGIN
  // ══════════════════════════════════════════════════════════════

  async function login() {
    const nameEl    = document.getElementById('inp-name');
    const acctEl    = document.getElementById('inp-account-pass');
    const chatEl    = document.getElementById('inp-chat-pass');
    const tosEl     = document.getElementById('chk-tos');
    const errEl     = document.getElementById('login-error');
    const btn       = document.getElementById('btn-login');
    const btnLabel  = document.getElementById('btn-label');
    const btnSpin   = document.getElementById('btn-spinner');

    const name        = nameEl.value.trim();
    const accountPass = acctEl.value;
    const chatPass    = chatEl.value;

    errEl.textContent = '';
    errEl.classList.remove('visible');

    // ── Validation ─────────────────────────────────────────────
    if (!name || name.length < 2) {
      errEl.textContent = 'Username must be at least 2 characters.';
      nameEl.focus(); return;
    }
    if (!/^[a-zA-Z0-9_\-\. ]+$/.test(name)) {
      errEl.textContent = 'Username: letters, numbers, spaces, hyphens, underscores, dots only.';
      nameEl.focus(); return;
    }
    if (!accountPass) {
      errEl.textContent = 'Account Password is required.';
      acctEl.focus(); return;
    }
    if (accountPass.length < 6) {
      errEl.textContent = 'Account Password must be at least 6 characters.';
      acctEl.focus(); return;
    }
    if (!tosEl.checked) {
      errEl.textContent = 'Please accept the Terms of Service to continue.';
      return;
    }

    btn.disabled = true;
    btnLabel.textContent = 'Loading crypto…';
    btnSpin.classList.remove('hidden');

    // ── Load CryptoJS ──────────────────────────────────────────
    try { await Crypto.init(); }
    catch (e) {
      _loginErr('Could not load encryption library. Check your internet connection.');
      return;
    }

    // ── Derive auth token (account password → hash; never sent raw) ─
    let authToken;
    try { authToken = Crypto.deriveAuthToken(name, accountPass); }
    catch (e) { _loginErr('Encryption error: ' + e.message); return; }

    // ── Reset state ────────────────────────────────────────────
    state.me           = name;
    state.chatPassword = chatPass || 'securechat_default_no_password';
    state.keyCache     = {};
    state.chats        = {};
    state.unread       = {};
    state.online       = new Set();
    state.active       = null;

    btnLabel.textContent = 'Connecting…';

    // Hook intercepts next server packet to handle login success/failure
    _loginHook = (pkt) => {
      if (pkt.type === 'error')   { Network.disconnect(); _loginErr(pkt.message); return true; }
      if (pkt.type === 'welcome') { _enterApp(name, pkt.new_account); return true; }
      return false;
    };

    Network.connect(name, authToken);
  }

  let _loginHook = null;

  function _loginErr(msg) {
    Network.disconnect();  // stop any reconnect loop
    const errEl = document.getElementById('login-error');
    errEl.textContent = msg;
    errEl.classList.add('visible');
    const btn = document.getElementById('btn-login');
    btn.disabled = false;
    document.getElementById('btn-label').textContent = 'Sign In / Register';
    document.getElementById('btn-spinner').classList.add('hidden');
    _loginHook = null;
  }

  function _enterApp(name, isNew) {
    _loginHook = null;
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');

    const myAv = document.getElementById('my-avatar');
    myAv.innerHTML = '';
    myAv.appendChild(UI.createAvatar(name, 36));
    document.getElementById('my-name').textContent = name;

    UI.setupInput();
    UI.renderContacts();

    UI.showToast(
      isNew ? 'Account created! Welcome to SecureChat 🎉' : `Welcome back, ${name}!`,
      'success'
    );
  }

  function logout() {
    Network.disconnect();
    Object.assign(state, {
      me: null, chatPassword: null, keyCache: {},
      chats: {}, unread: {}, online: new Set(), active: null,
    });
    document.getElementById('app').classList.add('hidden');
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('btn-login').disabled = false;
    document.getElementById('btn-label').textContent = 'Sign In / Register';
    document.getElementById('btn-spinner').classList.add('hidden');
    document.getElementById('login-error').textContent = '';
  }

  // ══════════════════════════════════════════════════════════════
  // CHAT
  // ══════════════════════════════════════════════════════════════

  function openChat(uname) {
    state.active       = uname;
    state.unread[uname] = 0;
    UI.openChatView(uname);
    UI.renderContacts(document.getElementById('search-input').value);

    // Send read receipt for last unread incoming message
    const msgs = state.chats[uname] || [];
    for (let i = msgs.length - 1; i >= 0; i--) {
      if (!msgs[i].mine && msgs[i].id) { Network.sendRead(uname, msgs[i].id); break; }
    }
  }

  function sendMessage() {
    const input  = document.getElementById('msg-input');
    const target = state.active;
    const text   = input.value.trim();
    if (!text || !target) return;

    input.value = ''; input.style.height = 'auto';

    let enc;
    try {
      enc = Crypto.encrypt(text, state.me, target, state.chatPassword, state.keyCache);
    } catch (e) {
      UI.showToast('Encryption error: ' + e.message, 'error');
      input.value = text; return;
    }

    if (!Network.sendMessage(target, enc.iv, enc.ciphertext)) {
      UI.showToast('Not connected — message not sent.', 'error');
      input.value = text; return;
    }

    const msg = { id: _uid(), from: state.me, text, ts: Date.now(), mine: true };
    if (!state.chats[target]) state.chats[target] = [];
    state.chats[target].push(msg);
    UI.appendBubble(target, msg);
    UI.renderContacts(document.getElementById('search-input').value);
  }

  // ── Input helpers ───────────────────────────────────────────────

  function _onMsgInput(e) {
    // Auto-resize textarea
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 130) + 'px';
    // Typing indicator
    if (state.active) Network.sendTyping(state.active);
  }

  function _onMsgKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  }

  // ══════════════════════════════════════════════════════════════
  // NETWORK CALLBACKS (called by Network module)
  // ══════════════════════════════════════════════════════════════

  function onWelcome(pkt) {
    if (_loginHook && _loginHook(pkt)) return;
  }

  function onUserList(users) {
    if (_loginHook && _loginHook({ type: 'user_list', users })) return;
    state.online = new Set(users);
    UI.renderContacts(document.getElementById('search-input').value);
    _refreshHdrStatus();
  }

  function onHistory(messages) {
    if (_loginHook) { _loginHook({ type: 'history' }); _loginHook = null; }
    _rawHistory = messages;   // cache raw for "Change Key" re-decrypt
    state.chats = {};
    for (const m of messages) {
      const peer = m.from_user === state.me ? m.to_user : m.from_user;
      const mine = m.from_user === state.me;
      let text;
      try { text = Crypto.decrypt({ iv: m.iv, ciphertext: m.ciphertext }, state.me, peer, state.chatPassword, state.keyCache); }
      catch { text = '🔒 [cannot decrypt — wrong Chat Password?]'; }
      if (!state.chats[peer]) state.chats[peer] = [];
      state.chats[peer].push({ id: `srv_${m.id}`, from: m.from_user, text, ts: Math.round(m.sent_at * 1000), mine });
    }
    UI.renderContacts(document.getElementById('search-input').value);
    if (state.active) UI.renderMessages(state.active);
  }

  function onMessage(pkt) {
    if (_loginHook && _loginHook(pkt)) return;
    const sender = pkt.from;
    let text;
    try { text = Crypto.decrypt({ iv: pkt.iv, ciphertext: pkt.ciphertext }, state.me, sender, state.chatPassword, state.keyCache); }
    catch { UI.showToast(`⚠️ Cannot decrypt message from ${sender}. Check Chat Password.`, 'error'); return; }

    const ts  = pkt.ts ? Math.round(pkt.ts * 1000) : Date.now();
    const msg = { id: pkt.id || _uid(), from: sender, text, ts, mine: false };
    if (!state.chats[sender]) state.chats[sender] = [];
    state.chats[sender].push(msg);

    if (state.active === sender) {
      UI.appendBubble(sender, msg);
      UI.hideTyping();
      if (pkt.id) Network.sendRead(sender, pkt.id);
    } else {
      state.unread[sender] = (state.unread[sender] || 0) + 1;
      UI.showToast(`💬 ${sender}: ${text.slice(0, 55)}${text.length > 55 ? '…' : ''}`);
    }
    UI.renderContacts(document.getElementById('search-input').value);
  }

  function onTyping(from) { UI.showTyping(from); }
  function onRead(from, id) { UI.markRead(id); }

  function onServerError(msg) {
    if (_loginHook) _loginErr(msg);
    else UI.showToast('Server: ' + msg, 'error');
  }

  function onDisconnected() {
    if (!state.me) return;
    state.online = new Set();
    UI.renderContacts();
    _refreshHdrStatus();
  }

  function _refreshHdrStatus() {
    if (!state.active) return;
    const el = document.getElementById('hdr-status');
    if (!el) return;
    const on = state.online.has(state.active);
    el.innerHTML = on
      ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg> end-to-end encrypted'
      : '<span style="color:var(--faint)">offline · message stored for delivery</span>';
  }

  // ══════════════════════════════════════════════════════════════
  // LOGIN FIELD LIVE FEEDBACK
  // ══════════════════════════════════════════════════════════════

  function _onNameInput(e) {
    const hint  = document.getElementById('name-hint');
    const inp   = e.target;
    const v     = inp.value.trim();
    if (!v) {
      hint.textContent = ''; hint.className = 'field-hint';
      inp.classList.remove('valid','invalid'); return;
    }
    if (v.length < 2) {
      hint.textContent = 'At least 2 characters';
      hint.className = 'field-hint warn';
      inp.classList.add('invalid'); inp.classList.remove('valid'); return;
    }
    if (!/^[a-zA-Z0-9_\-\. ]+$/.test(v)) {
      hint.textContent = 'Letters, numbers, spaces, - _ . only';
      hint.className = 'field-hint warn';
      inp.classList.add('invalid'); inp.classList.remove('valid'); return;
    }
    hint.textContent = '✓ Valid username';
    hint.className = 'field-hint success';
    inp.classList.add('valid'); inp.classList.remove('invalid');
  }

  function _onAccountPassInput(e) {
    const bar  = document.getElementById('strength-bar');
    const txt  = document.getElementById('strength-text');
    const n    = e.target.value.length;
    let w = 0, c = '', label = '';
    if (!n) { bar.style.width = '0'; if (txt) { txt.textContent = ''; txt.style.color=''; } return; }
    if (n < 6)  { w = 18; c = 'var(--red)';     label = 'Weak — min 6 characters'; }
    else if (n < 10) { w = 48; c = 'var(--warning)';  label = 'Fair'; }
    else if (n < 16) { w = 75; c = 'var(--blue-h)';   label = 'Good'; }
    else             { w = 100; c = 'var(--green)'; label = 'Strong ✓'; }
    bar.style.width = w + '%'; bar.style.background = c;
    if (txt) { txt.textContent = label; txt.style.color = c; }
  }

  function _togglePass(inputId) {
    const inp = document.getElementById(inputId);
    inp.type  = inp.type === 'password' ? 'text' : 'password';
  }

  // ── Change Chat Key: re-decrypt history without re-login ──────────

  // Raw encrypted history cache (set in onHistory)
  let _rawHistory = [];

  function _applyNewChatKey() {
    const newPass = document.getElementById('key-prompt-input').value.trim();
    if (!newPass) { UI.showToast('Enter a Chat Password first.', 'error'); return; }

    state.chatPassword = newPass;
    state.keyCache     = {};

    // Re-decrypt from raw history cache
    state.chats = {};
    for (const m of _rawHistory) {
      const peer = m.from_user === state.me ? m.to_user : m.from_user;
      const mine = m.from_user === state.me;
      let text;
      try { text = Crypto.decrypt({ iv: m.iv, ciphertext: m.ciphertext }, state.me, peer, newPass, state.keyCache); }
      catch { text = '🔒 [cannot decrypt — wrong Chat Password?]'; }
      if (!state.chats[peer]) state.chats[peer] = [];
      state.chats[peer].push({ id: `srv_${m.id}`, from: m.from_user, text, ts: Math.round(m.sent_at * 1000), mine });
    }

    document.getElementById('key-prompt').classList.add('hidden');
    document.getElementById('key-prompt-input').value = '';
    UI.renderContacts(document.getElementById('search-input').value || '');
    if (state.active) UI.renderMessages(state.active);
    UI.showToast('Chat key updated — messages re-decrypted.', 'success');
  }

  // ══════════════════════════════════════════════════════════════
  // ToS MODAL
  // ══════════════════════════════════════════════════════════════
  function _showTos()  { document.getElementById('tos-modal').classList.remove('hidden'); }
  function _closeTos() { document.getElementById('tos-modal').classList.add('hidden'); }
  function _acceptTos(){ document.getElementById('chk-tos').checked = true; _closeTos(); }

  // ══════════════════════════════════════════════════════════════
  // INIT — wire all DOM events (no inline handlers needed)
  // ══════════════════════════════════════════════════════════════

  function _init() {
    // ── Login form ─────────────────────────────────────────────
    document.getElementById('login-form').addEventListener('submit', (e) => {
      e.preventDefault(); login();
    });

    document.getElementById('inp-name').addEventListener('input',   _onNameInput);
    document.getElementById('inp-name').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); document.getElementById('inp-account-pass').focus(); }
    });

    document.getElementById('inp-account-pass').addEventListener('input',   _onAccountPassInput);
    document.getElementById('inp-account-pass').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); document.getElementById('inp-chat-pass').focus(); }
    });

    document.getElementById('inp-chat-pass').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); login(); }
    });

    document.getElementById('eye-account-btn').addEventListener('click', () => _togglePass('inp-account-pass'));
    document.getElementById('eye-chat-btn').addEventListener('click',    () => _togglePass('inp-chat-pass'));
    document.getElementById('btn-login').addEventListener('click',       (e) => { e.preventDefault(); login(); });

    // ── ToS ────────────────────────────────────────────────────
    document.getElementById('tos-link-btn').addEventListener('click',  _showTos);
    document.getElementById('tos-close-btn').addEventListener('click', _closeTos);
    document.getElementById('tos-accept-btn').addEventListener('click', _acceptTos);
    document.getElementById('tos-backdrop').addEventListener('click',   _closeTos);

    // ── App sidebar ────────────────────────────────────────────
    document.getElementById('logout-btn').addEventListener('click', logout);
    document.getElementById('search-input').addEventListener('input', (e) => UI.filterContacts(e.target.value));

    // ── Chat header ─────────────────────────────────────────────
    document.getElementById('back-btn').addEventListener('click', UI.closeChat);

    // ── Message input ──────────────────────────────────────────
    document.getElementById('msg-input').addEventListener('input',   _onMsgInput);
    document.getElementById('msg-input').addEventListener('keydown', _onMsgKeydown);

    // ── Buttons ─────────────────────────────────────────────────
    document.getElementById('send-btn').addEventListener('click',       sendMessage);
    document.getElementById('emoji-toggle-btn').addEventListener('click', UI.toggleEmojiPicker);
    document.getElementById('scroll-fab').addEventListener('click',     () => UI.scrollToBottom(true));

    // ── Change Chat Key (decrypt with different password) ────────
    document.getElementById('change-key-btn').addEventListener('click', () => {
      document.getElementById('key-prompt').classList.remove('hidden');
      document.getElementById('key-prompt-input').value = '';
      document.getElementById('key-prompt-input').focus();
    });
    document.getElementById('key-prompt-cancel').addEventListener('click', () => {
      document.getElementById('key-prompt').classList.add('hidden');
    });
    document.getElementById('key-prompt-submit').addEventListener('click', _applyNewChatKey);
    document.getElementById('key-prompt-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); _applyNewChatKey(); }
      if (e.key === 'Escape') document.getElementById('key-prompt').classList.add('hidden');
    });

    // ── Global keyboard shortcuts ──────────────────────────────
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') _closeTos();
    });
  }

  // Wire up after DOM is ready
  document.addEventListener('DOMContentLoaded', _init);

  // ── Public API ─────────────────────────────────────────────────
  return {
    state,
    // Network callbacks (called by network.js)
    onWelcome, onUserList, onHistory,
    onMessage, onTyping, onRead,
    onServerError, onDisconnected,
    // Used by ui.js
    openChat, sendMessage,
  };
})();

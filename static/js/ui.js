/**
 * SecureChat — UI Module  (ui.js)
 * =================================
 * All DOM rendering: avatars, contact list, message bubbles,
 * typing indicator, emoji picker, toasts, and scroll behaviour.
 */

const UI = (() => {

  // Avatar colours — only blue and green system, no extras
  const PALETTE = [
    '#1D4ED8', '#1e40af', '#1d3faa', '#163890',
    '#15803d', '#166534', '#22C55E', '#16a34a',
  ];

  function _palette(name) {
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return PALETTE[h % PALETTE.length];
  }

  function createAvatar(name, size = 40) {
    const color = _palette(name);
    const el = document.createElement('div');
    el.className = 'avatar';
    el.style.cssText = `width:${size}px;height:${size}px;font-size:${Math.round(size*.4)}px;background:${color};`;
    el.textContent = name.charAt(0).toUpperCase();
    el.title = name;
    return el;
  }

  // ── Contact list ────────────────────────────────────────────────

  function renderContacts(filter = '') {
    const list   = document.getElementById('contacts-list');
    const empty  = document.getElementById('contacts-empty');
    const cntEl  = document.getElementById('online-count');
    const { me, online, chats, unread, active } = App.state;

    const peers = [...online].filter(u => u !== me);
    cntEl.textContent = peers.length;

    const allContacts = new Set([
      ...peers,
      ...Object.keys(chats).filter(u => u !== me),
    ]);

    const lc       = (filter || '').toLowerCase();
    const filtered = [...allContacts].filter(u => u !== me && u.toLowerCase().includes(lc));

    filtered.sort((a, b) => {
      const ua = unread[a] || 0, ub = unread[b] || 0;
      if (ua !== ub) return ub - ua;
      const ao = online.has(a) ? 1 : 0, bo = online.has(b) ? 1 : 0;
      if (ao !== bo) return bo - ao;
      return _lastTs(b) - _lastTs(a);
    });

    list.innerHTML = '';

    if (filtered.length === 0) {
      empty.classList.remove('hidden');
    } else {
      empty.classList.add('hidden');
      for (const u of filtered) list.appendChild(_contactItem(u, active === u, online.has(u)));
    }
  }

  function _lastTs(u) {
    const m = App.state.chats[u]; return m && m.length > 0 ? m[m.length - 1].ts : 0;
  }

  function _lastPreview(u) {
    const m = App.state.chats[u];
    if (!m || !m.length) return '';
    const last = m[m.length - 1];
    return (last.mine ? 'You: ' : '') + _trunc(last.text, 36);
  }

  function _contactItem(uname, isActive, isOnline) {
    const item = document.createElement('div');
    item.className = `contact-item${isActive ? ' active' : ''}`;
    item.onclick   = () => App.openChat(uname);

    // Avatar with optional online ring
    const wrap = document.createElement('div');
    wrap.className = 'av-wrap';
    wrap.appendChild(createAvatar(uname, 40));
    if (isOnline) {
      const ring = document.createElement('div');
      ring.className = 'av-ring';
      wrap.appendChild(ring);
    }
    item.appendChild(wrap);

    const badge   = App.state.unread[uname] || 0;
    const last    = _lastPreview(uname);
    const ts      = _lastTs(uname);

    const info = document.createElement('div');
    info.className = 'contact-info';
    info.innerHTML = `
      <div class="contact-name">
        <span>${_esc(uname)}</span>
        ${!isOnline ? '<span class="offline-tag">offline</span>' : ''}
      </div>
      ${last ? `<div class="contact-preview">${_esc(last)}</div>` : ''}
    `;
    item.appendChild(info);

    const meta = document.createElement('div');
    meta.className = 'contact-meta';
    meta.innerHTML = `
      ${ts ? `<span class="contact-time">${_fmtTime(ts)}</span>` : ''}
      ${badge ? `<span class="unread-badge">${badge > 99 ? '99+' : badge}</span>` : ''}
    `;
    item.appendChild(meta);

    return item;
  }

  function filterContacts(q) { renderContacts(q); }

  // ── Chat view ────────────────────────────────────────────────────

  function openChatView(uname) {
    document.getElementById('empty-state').classList.add('hidden');
    document.getElementById('chat-view').classList.remove('hidden');
    document.getElementById('sidebar').classList.add('behind');
    document.querySelector('.chat-area').classList.add('open'); // mobile slide-in

    const hdrAv = document.getElementById('hdr-avatar');
    hdrAv.innerHTML = '';
    hdrAv.appendChild(createAvatar(uname, 36));
    document.getElementById('hdr-name').textContent = uname;

    const isOnline = App.state.online.has(uname);
    const st = document.getElementById('hdr-status');
    st.innerHTML = isOnline
      ? `<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg> end-to-end encrypted`
      : `<span style="color:var(--faint)">offline · delivered when they reconnect</span>`;

    renderMessages(uname);
    document.getElementById('msg-input').focus();
  }

  function closeChat() {
    document.getElementById('sidebar').classList.remove('behind');
    document.getElementById('chat-view').classList.add('hidden');
    document.getElementById('empty-state').classList.remove('hidden');
    document.querySelector('.chat-area').classList.remove('open'); // mobile slide-out
    document.getElementById('decrypt-warn').classList.add('hidden');
    App.state.active = null;
  }

  function renderMessages(uname) {
    const pane = document.getElementById('messages-pane');
    pane.innerHTML = '';
    const msgs = App.state.chats[uname] || [];

    // Count decryption failures
    const failCount  = msgs.filter(m => m.text && m.text.startsWith('\uD83D\uDD12 [cannot')).length;
    const warnEl     = document.getElementById('decrypt-warn');
    if (failCount > 0 && failCount >= Math.max(1, msgs.length * 0.3)) {
      warnEl.classList.remove('hidden');
    } else {
      warnEl.classList.add('hidden');
    }

    let lastDate = null;
    for (const msg of msgs) {
      const d = _fmtDate(msg.ts);
      if (d !== lastDate) {
        lastDate = d;
        const sep = document.createElement('div');
        sep.className = 'date-sep';
        sep.innerHTML = `<div class="date-label">${d}</div>`;
        pane.appendChild(sep);
      }
      pane.appendChild(_buildBubble(msg, uname));
    }
    scrollToBottom(false);
  }

  function _buildBubble(msg, peerName) {
    const row = document.createElement('div');
    row.className = `msg-row ${msg.mine ? 'mine' : 'theirs'}`;
    row.dataset.msgId = msg.id || '';

    if (!msg.mine) {
      const av = document.createElement('div');
      av.className = 'msg-av';
      av.appendChild(createAvatar(peerName || msg.from, 28));
      row.appendChild(av);
    }

    const isFail = msg.text && msg.text.startsWith('\uD83D\uDD12 [cannot');
    const bubble = document.createElement('div');
    bubble.className = 'bubble' + (isFail ? ' bubble-fail' : '');
    const displayText = isFail ? '\uD83D\uDD12 Encrypted with a different key' : _esc(msg.text);
    bubble.innerHTML = `
      <div class="bubble-text">${displayText}</div>
      <div class="bubble-meta">
        <span class="bubble-time">${_fmtTime(msg.ts)}</span>
        ${msg.mine ? `<span class="bubble-tick" id="tick-${msg.id}">✓✓</span>` : ''}
      </div>
    `;
    row.appendChild(bubble);
    return row;
  }

  // Public (called from App.appendBubble path)
  function buildBubble(msg, peerName) { return _buildBubble(msg, peerName); }

  function appendBubble(uname, msg) {
    if (App.state.active !== uname) return;
    const pane = document.getElementById('messages-pane');
    const msgs = App.state.chats[uname] || [];

    // Date separator if day rolled over
    if (msgs.length > 1) {
      const prev = msgs[msgs.length - 2];
      if (_fmtDate(prev.ts) !== _fmtDate(msg.ts)) {
        const sep = document.createElement('div');
        sep.className = 'date-sep';
        sep.innerHTML = `<div class="date-label">${_fmtDate(msg.ts)}</div>`;
        pane.appendChild(sep);
      }
    }

    pane.appendChild(_buildBubble(msg, uname));
    const near = pane.scrollHeight - pane.scrollTop - pane.clientHeight < 140;
    if (near) scrollToBottom(true);
    else document.getElementById('scroll-fab').classList.remove('hidden');
  }

  // ── Typing indicator ──────────────────────────────────────────────

  let _typingTimer = null;

  function showTyping(from) {
    if (App.state.active !== from) return;
    document.getElementById('typing-name').textContent = from;
    document.getElementById('typing-bar').classList.remove('hidden');
    clearTimeout(_typingTimer);
    _typingTimer = setTimeout(() => document.getElementById('typing-bar').classList.add('hidden'), 3500);
  }

  function hideTyping() {
    clearTimeout(_typingTimer);
    document.getElementById('typing-bar').classList.add('hidden');
  }

  // ── Read receipts ──────────────────────────────────────────────────

  function markRead(id) {
    const el = document.getElementById(`tick-${id}`);
    if (el) el.classList.add('read');
  }

  // ── Emoji picker ───────────────────────────────────────────────────

  const EMOJIS = [
    '😀','😃','😄','😁','😅','🤣','😂','🙂','😊','😇','🥰','😍','🤩','😘','😗','😚',
    '😙','😛','😜','🤪','😝','🤑','🤗','🤔','🤨','😐','😑','🙄','😏','😒','😞','😔',
    '😟','😕','🙁','😣','😖','😫','😩','🥺','😢','😭','😤','😠','😡','🤬','😈','👿',
    '💀','💩','🤡','👹','👻','👽','💋','❤️','🧡','💛','💚','💙','💜','🖤','💔','💕',
    '💞','💓','💗','👍','👎','👊','✊','🤞','✌️','🤟','👌','👋','🙌','👏','🙏','💪',
    '🔥','💥','✨','⭐','💫','🎉','🎊','🎈','🎁','😺','😸','😹','😻','😼','😿','😾',
    '🙈','🙉','🙊','🌍','🌏','🚀','💎','🏆','📱','💻','🔐','🛡️','⚡','🌊','🍀','🎯',
  ];

  let _emojiOpen = false;

  function toggleEmojiPicker() {
    const p = document.getElementById('emoji-picker');
    if (!_emojiOpen) {
      if (!p.childElementCount) {
        p.innerHTML = '';
        EMOJIS.forEach(e => {
          const b = document.createElement('button');
          b.textContent = e; b.title = e;
          b.onclick = () => {
            const inp = document.getElementById('msg-input');
            const s   = inp.selectionStart;
            inp.value = inp.value.slice(0, s) + e + inp.value.slice(inp.selectionEnd);
            inp.selectionStart = inp.selectionEnd = s + e.length;
            inp.focus(); _autoResize(inp);
          };
          p.appendChild(b);
        });
      }
      p.classList.remove('hidden');
    } else {
      p.classList.add('hidden');
    }
    _emojiOpen = !_emojiOpen;
  }

  document.addEventListener('click', e => {
    if (_emojiOpen
        && !document.getElementById('emoji-picker').contains(e.target)
        && !document.getElementById('emoji-toggle-btn').contains(e.target)) {
      document.getElementById('emoji-picker').classList.add('hidden');
      _emojiOpen = false;
    }
  });

  // ── Toast ──────────────────────────────────────────────────────────

  function showToast(msg, type = '', ms = 3500) {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = `toast${type ? ' ' + type : ''}`;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => {
      t.style.animation = 'toastOut .22s ease forwards';
      setTimeout(() => t.remove(), 230);
    }, ms);
  }

  // ── Scroll ─────────────────────────────────────────────────────────

  function scrollToBottom(smooth = true) {
    const p = document.getElementById('messages-pane');
    if (!p) return;
    p.scrollTo({ top: p.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
    document.getElementById('scroll-fab').classList.add('hidden');
  }

  function setupInput() {
    const inp = document.getElementById('msg-input');
    inp.addEventListener('input', () => _autoResize(inp));

    const pane = document.getElementById('messages-pane');
    const fab  = document.getElementById('scroll-fab');
    pane.addEventListener('scroll', () => {
      fab.classList.toggle('hidden', pane.scrollHeight - pane.scrollTop - pane.clientHeight < 80);
    });
  }

  // ── Utilities ───────────────────────────────────────────────────────

  function _autoResize(ta) {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 130) + 'px';
  }

  function _esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function _trunc(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }

  function _fmtDate(ts) {
    const d = new Date(ts), t = new Date();
    if (d.toDateString() === t.toDateString()) return 'Today';
    const y = new Date(t); y.setDate(t.getDate() - 1);
    if (d.toDateString() === y.toDateString()) return 'Yesterday';
    return d.toLocaleDateString(undefined, { day:'numeric', month:'short', year:'numeric' });
  }

  function _fmtTime(ts) {
    return new Date(ts).toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit' });
  }

  function focusSearch() { document.getElementById('search-input').focus(); }

  return {
    createAvatar,
    renderContacts, filterContacts,
    openChatView, closeChat,
    renderMessages, buildBubble, appendBubble,
    showTyping, hideTyping,
    markRead,
    toggleEmojiPicker,
    showToast,
    scrollToBottom, setupInput,
    focusSearch,
  };
})();

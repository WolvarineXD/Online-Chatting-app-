/**
 * SecureChat — Crypto Module  (crypto.js)
 * =========================================
 * AES-256-CBC message encryption using CryptoJS (loaded from CDN).
 * Also provides a client-side auth token derivation so the plaintext
 * account password is NEVER sent over the network.
 *
 * Key design:
 *   • authToken   = PBKDF2(accountPassword, username+"_sc_auth_v2", 10 000)
 *                   → sent to server for account authentication
 *   • pairKey     = PBKDF2(chatPassword, sorted(userA,userB)+"_sc_msg", 5 000)
 *                   → used to AES-256 encrypt/decrypt messages
 *                   → NEVER sent to server
 */

const Crypto = (() => {
  let _ready = false;

  function _loadScript(src) {
    return new Promise((resolve, reject) => {
      if (document.querySelector(`script[src="${src}"]`)) { resolve(); return; }
      const s = document.createElement('script');
      s.src = src; s.onload = resolve;
      s.onerror = () => reject(new Error('Failed to load: ' + src));
      document.head.appendChild(s);
    });
  }

  async function init() {
    if (_ready) return;
    if (!window.CryptoJS)
      await _loadScript('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js');
    if (!window.CryptoJS) throw new Error('CryptoJS could not be loaded.');
    _ready = true;
  }

  /**
   * Derive the account authentication token.
   * This replaces the plaintext password in the hello packet.
   * The server re-hashes this with PBKDF2 + a per-user salt before storing.
   *
   * @param {string} username
   * @param {string} accountPassword
   * @returns {string} hex string
   */
  function deriveAuthToken(username, accountPassword) {
    if (!_ready) throw new Error('Crypto.init() not called.');
    const salt = CryptoJS.enc.Utf8.parse(username.toLowerCase() + '_sc_auth_v2');
    return CryptoJS.PBKDF2(accountPassword, salt, { keySize: 256 / 32, iterations: 10_000 })
                   .toString(CryptoJS.enc.Hex);
  }

  /**
   * Derive the AES pair-key for a (me ↔ peer) conversation.
   * Derived from the chat password — never from the account password.
   * Cached in keyCache to avoid recomputing on every message.
   *
   * @param {string} chatPassword
   * @param {string} me
   * @param {string} peer
   * @param {object} keyCache   mutable { peer: WordArray }
   * @returns {CryptoJS.lib.WordArray}
   */
  function _pairKey(chatPassword, me, peer, keyCache) {
    if (keyCache[peer]) return keyCache[peer];
    const pair  = [me, peer].sort().join(':');
    const salt  = CryptoJS.enc.Utf8.parse(pair + '_sc_msg_v2');
    const key   = CryptoJS.PBKDF2(chatPassword, salt, { keySize: 256 / 32, iterations: 5_000 });
    keyCache[peer] = key;
    return key;
  }

  /**
   * Encrypt a plaintext message for *peer*.
   * @returns {{ iv: string, ciphertext: string }}  both base64-encoded
   */
  function encrypt(text, me, peer, chatPassword, keyCache) {
    if (!_ready) throw new Error('Crypto.init() not called.');
    const key = _pairKey(chatPassword, me, peer, keyCache);
    const iv  = CryptoJS.lib.WordArray.random(16);
    const enc = CryptoJS.AES.encrypt(text, key, {
      iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7,
    });
    return {
      iv:         iv.toString(CryptoJS.enc.Base64),
      ciphertext: enc.ciphertext.toString(CryptoJS.enc.Base64),
    };
  }

  /**
   * Decrypt a message packet from *peer*.
   * @throws {Error} if decryption fails (wrong password / corrupted data)
   * @returns {string} plaintext
   */
  function decrypt(pkt, me, peer, chatPassword, keyCache) {
    if (!_ready) throw new Error('Crypto.init() not called.');
    const key = _pairKey(chatPassword, me, peer, keyCache);
    const iv  = CryptoJS.enc.Base64.parse(pkt.iv);
    const ct  = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(pkt.ciphertext),
    });
    const dec    = CryptoJS.AES.decrypt(ct, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    const result = dec.toString(CryptoJS.enc.Utf8);
    if (!result) throw new Error('Decryption failed — wrong chat password or corrupted message.');
    return result;
  }

  return { init, deriveAuthToken, encrypt, decrypt };
})();

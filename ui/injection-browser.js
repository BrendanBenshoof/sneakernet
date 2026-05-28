// ═══════════════════════════════════════════════════════════════════════
//  XChaCha20-Poly1305
//  Implements RFC 8439 ChaCha20-Poly1305 + draft-irtf-cfrg-xchacha-03.
// ═══════════════════════════════════════════════════════════════════════

const _CC = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function _u32(b, i) {
  return ((b[i]) | (b[i+1]<<8) | (b[i+2]<<16) | (b[i+3]<<24)) >>> 0;
}
function _s32(b, i, v) {
  v >>>= 0;
  b[i]=v&255; b[i+1]=(v>>>8)&255; b[i+2]=(v>>>16)&255; b[i+3]=(v>>>24)&255;
}
function _rotl(x, n) { return ((x<<n)|(x>>>(32-n)))>>>0; }

function _qr(s, a, b, c, d) {
  s[a]=(s[a]+s[b])>>>0; s[d]=_rotl(s[d]^s[a],16);
  s[c]=(s[c]+s[d])>>>0; s[b]=_rotl(s[b]^s[c],12);
  s[a]=(s[a]+s[b])>>>0; s[d]=_rotl(s[d]^s[a], 8);
  s[c]=(s[c]+s[d])>>>0; s[b]=_rotl(s[b]^s[c], 7);
}

function _rounds(s) {
  for (let i=0; i<10; i++) {
    _qr(s,0,4,8,12); _qr(s,1,5,9,13); _qr(s,2,6,10,14); _qr(s,3,7,11,15);
    _qr(s,0,5,10,15); _qr(s,1,6,11,12); _qr(s,2,7,8,13); _qr(s,3,4,9,14);
  }
}

function _hchacha20(key, n16) {
  const s = new Uint32Array(16);
  s[0]=_CC[0]; s[1]=_CC[1]; s[2]=_CC[2]; s[3]=_CC[3];
  for (let i=0;i<8;i++) s[4+i]=_u32(key,i*4);
  s[12]=_u32(n16,0); s[13]=_u32(n16,4); s[14]=_u32(n16,8); s[15]=_u32(n16,12);
  _rounds(s);
  const out = new Uint8Array(32);
  _s32(out, 0,s[0]); _s32(out, 4,s[1]); _s32(out, 8,s[2]); _s32(out,12,s[3]);
  _s32(out,16,s[12]);_s32(out,20,s[13]);_s32(out,24,s[14]);_s32(out,28,s[15]);
  return out;
}

function _block(key, counter, n12) {
  const s = new Uint32Array(16);
  s[0]=_CC[0]; s[1]=_CC[1]; s[2]=_CC[2]; s[3]=_CC[3];
  for (let i=0;i<8;i++) s[4+i]=_u32(key,i*4);
  s[12]=counter>>>0; s[13]=_u32(n12,0); s[14]=_u32(n12,4); s[15]=_u32(n12,8);
  const w = new Uint32Array(s);
  _rounds(w);
  const out = new Uint8Array(64);
  for (let i=0;i<16;i++) _s32(out,i*4,(w[i]+s[i])>>>0);
  return out;
}

function _xor(key, startCounter, n12, data) {
  const out = new Uint8Array(data.length);
  let pos=0, c=startCounter>>>0;
  while (pos < data.length) {
    const blk = _block(key, c++, n12);
    const n = Math.min(64, data.length-pos);
    for (let i=0;i<n;i++) out[pos+i]=data[pos+i]^blk[i];
    pos+=n;
  }
  return out;
}

const _P = (1n<<130n)-5n;
const _CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function _leBytes(b) {
  let n=0n;
  for (let i=b.length-1;i>=0;i--) n=(n<<8n)|BigInt(b[i]);
  return n;
}

function _poly1305(key32, ct) {
  const pad = ct.length%16===0?0:16-(ct.length%16);
  const mac = new Uint8Array(ct.length+pad+16);
  mac.set(ct);
  let L=ct.length;
  const off=ct.length+pad+8;
  for (let i=0;i<8;i++){mac[off+i]=L&255;L>>>=8;}

  const r = _leBytes(key32.slice(0,16)) & _CLAMP;
  const s = _leBytes(key32.slice(16,32));
  let acc=0n;
  for (let i=0;i<mac.length;i+=16) {
    const chunk=mac.slice(i,i+16);
    acc=((acc+(_leBytes(chunk)|(1n<<BigInt(chunk.length*8))))*r)%_P;
  }
  acc=(acc+s)&((1n<<128n)-1n);
  const tag=new Uint8Array(16);
  for (let i=0;i<16;i++){tag[i]=Number(acc&0xffn);acc>>=8n;}
  return tag;
}

function xchacha20Open(key, nonce24, sealed) {
  if (sealed.length < 16) throw new Error('too short');
  const subkey = _hchacha20(key, nonce24.slice(0,16));
  const n12 = new Uint8Array(12);
  n12.set(nonce24.slice(16), 4);

  const polyKey = _block(subkey, 0, n12).slice(0, 32);
  const ct  = sealed.slice(0, sealed.length-16);
  const tag = sealed.slice(sealed.length-16);

  const expected = _poly1305(polyKey, ct);
  let diff=0;
  for (let i=0;i<16;i++) diff|=tag[i]^expected[i];
  if (diff!==0) throw new Error('auth failed');

  return _xor(subkey, 1, n12, ct);
}

function xchacha20Seal(key, nonce24, plain) {
  const subkey = _hchacha20(key, nonce24.slice(0,16));
  const n12 = new Uint8Array(12);
  n12.set(nonce24.slice(16), 4);

  const polyKey = _block(subkey, 0, n12).slice(0, 32);
  const ct = _xor(subkey, 1, n12, plain);
  const tag = _poly1305(polyKey, ct);

  const out = new Uint8Array(ct.length+16);
  out.set(ct); out.set(tag, ct.length);
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
//  Web Crypto helpers
// ═══════════════════════════════════════════════════════════════════════

// X25519
async function genX25519Keypair() {
  return crypto.subtle.generateKey({name:'X25519'}, true, ['deriveBits']);
}
async function exportPubRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
async function exportPrivJWK(key) {
  return crypto.subtle.exportKey('jwk', key);
}
async function importPrivJWK(jwk) {
  return crypto.subtle.importKey('jwk', jwk, {name:'X25519'}, true, ['deriveBits']);
}
async function importX25519PubRaw(bytes) {
  return crypto.subtle.importKey('raw', bytes, {name:'X25519'}, false, []);
}
async function ecdh(privKey, theirPubBytes) {
  const pub = await importX25519PubRaw(theirPubBytes);
  const bits = await crypto.subtle.deriveBits({name:'X25519', public:pub}, privKey, 256);
  return new Uint8Array(bits);
}

// Ed25519
async function genEd25519Keypair() {
  return crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign', 'verify']);
}
async function exportEd25519PubRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
async function exportEd25519PrivJWK(key) {
  return crypto.subtle.exportKey('jwk', key);
}
async function importEd25519PrivJWK(jwk) {
  return crypto.subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['sign']);
}

// SHA-256
async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
async function sha256hex(data) {
  const h = await sha256(data);
  return Array.from(h).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Ed25519 → X25519 conversion (birational map between Edwards and Montgomery forms)
const P25519 = (1n << 255n) - 19n;
function _modp(n)      { return ((n % P25519) + P25519) % P25519; }
function _modpow(b,e,m){ let r=1n; b%=m; while(e>0n){if(e&1n)r=r*b%m;e>>=1n;b=b*b%m;} return r; }
function _leToBI(bytes){ let n=0n; for(let i=bytes.length-1;i>=0;i--)n=(n<<8n)|BigInt(bytes[i]); return n; }
function _biToLE32(n)  { const b=new Uint8Array(32); for(let i=0;i<32;i++){b[i]=Number(n&0xffn);n>>=8n;} return b; }

// Convert a 32-byte Ed25519 compressed point to a 32-byte X25519 Montgomery u coordinate.
function edPubToX25519Bytes(edPubBytes) {
  const b = new Uint8Array(edPubBytes);
  b[31] &= 0x7f; // clear sign bit to get y
  const y = _leToBI(b);
  // u = (1+y)/(1-y) mod p  (Elligator birational map)
  const u = _modp((1n + y) * _modpow(_modp(1n - y), P25519 - 2n, P25519));
  return _biToLE32(u);
}

// Derive an X25519 CryptoKey from an Ed25519 private key JWK.
// The scalar is SHA-512(seed)[0:32] with cofactor clamping — same derivation as Go.
// Must use pkcs8 format: 'raw' is for public keys only in Web Crypto's X25519 API.
async function edPrivJWKToX25519PrivKey(edPrivJWK) {
  const seed = b64dec(fromB64url(edPrivJWK.d));
  const h    = await crypto.subtle.digest('SHA-512', seed);
  const sc   = new Uint8Array(h).slice(0, 32);
  sc[0] &= 248; sc[31] &= 127; sc[31] |= 64;
  // PKCS#8 DER wrapper for X25519 (OID 1.3.101.110): 16-byte header + 32-byte scalar
  const pkcs8 = new Uint8Array(48);
  pkcs8.set([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20]);
  pkcs8.set(sc, 16);
  return crypto.subtle.importKey('pkcs8', pkcs8, {name:'X25519'}, false, ['deriveBits']);
}

// base64
function b64enc(bytes) { return btoa(String.fromCharCode(...bytes)); }
function b64dec(s)     { return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }

// hex
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}
function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) return null;
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return b;
}

// ═══════════════════════════════════════════════════════════════════════
//  Message format v2
//  Plaintext layout (4024 bytes):
//    [0:4]    magic SNK\x02
//    [4]      msg_type  (0=text)
//    [5]      flags
//    [6:14]   timestamp int64 LE ms
//    [14:46]  sender Ed25519 pub (zeros = anonymous)
//    [46:110] Ed25519 signature  (zeros = unsigned)
//    [110:366] thread_refs[8] x 32 bytes
//    [366:398] frag_id
//    [398:400] frag_index uint16 LE
//    [400:402] frag_total uint16 LE
//    [402:404] content_len uint16 LE
//    [404:]   content + padding
// ═══════════════════════════════════════════════════════════════════════

const PLAINTEXT_SIZE = 4024;
const MAX_CONTENT    = 3620;

async function buildV2Plain(msgText, senderEd25519PubBytes, signingPrivKey, threadRefHexes) {
  const msg = new TextEncoder().encode(msgText);
  if (msg.length > MAX_CONTENT) throw new Error(`Message too long (max ${MAX_CONTENT} bytes)`);
  const plain = new Uint8Array(PLAINTEXT_SIZE);

  plain[0]=0x53; plain[1]=0x4e; plain[2]=0x4b; plain[3]=0x02;
  // [4]=0 text, [5]=0 flags

  // timestamp ms as int64 LE at [6:14]
  const tsMs = BigInt(Date.now());
  for (let i = 0; i < 8; i++) plain[6+i] = Number((tsMs >> BigInt(i*8)) & 0xffn);

  // sender Ed25519 pub at [14:46]
  if (senderEd25519PubBytes) plain.set(senderEd25519PubBytes, 14);
  // signature field [46:110] stays zero until signing

  // thread_refs [110:366] — 8 slots x 32 bytes
  if (threadRefHexes) {
    for (let i = 0; i < Math.min(8, threadRefHexes.length); i++) {
      const rb = hexToBytes(threadRefHexes[i]);
      if (rb && rb.length === 32) plain.set(rb, 110 + i*32);
    }
  }

  // frag_total = 1 at [400:402]
  plain[400] = 1;

  // content_len at [402:404]
  plain[402] = msg.length & 0xff;
  plain[403] = (msg.length >> 8) & 0xff;
  plain.set(msg, 404);

  // sign with signature field zeroed (already 0)
  if (signingPrivKey && senderEd25519PubBytes) {
    const sig = new Uint8Array(await crypto.subtle.sign({name:'Ed25519'}, signingPrivKey, plain));
    plain.set(sig, 46);
  }

  return plain;
}

function readV2PlainFull(plain) {
  if (plain[0]!==0x53||plain[1]!==0x4e||plain[2]!==0x4b||plain[3]!==0x02) return null;
  const msgType = plain[4];

  // timestamp LE int64
  let tsMs = 0n;
  for (let i = 7; i >= 0; i--) tsMs = (tsMs << 8n) | BigInt(plain[6+i]);
  const sentAt = tsMs > 0n ? new Date(Number(tsMs)).toISOString() : null;

  // sender Ed25519 pub [14:46]
  const spb = plain.slice(14, 46);
  const senderPub = spb.every(b=>b===0) ? '' : b64enc(spb);

  // thread_refs [110:366]
  const threadRefs = [];
  for (let i = 0; i < 8; i++) {
    threadRefs.push(bytesToHex(plain.slice(110 + i*32, 142 + i*32)));
  }

  const msgLen = plain[402] | (plain[403]<<8);
  if (msgLen > MAX_CONTENT) return null;

  return {msgType, sentAt, senderPub, threadRefs, contentB64: b64enc(plain.slice(404, 404+msgLen))};
}

function readV1Plain(plain) {
  if (plain[0]!==0x53||plain[1]!==0x4e||plain[2]!==0x4b||plain[3]!==0x01) return null;
  const msgLen = plain[4] | (plain[5]<<8);
  if (msgLen > 1970) return null;
  return {
    msgType: 0, sentAt: null, senderPub: '',
    threadRefs: Array(8).fill('0'.repeat(64)),
    contentB64: b64enc(plain.slice(6, 6+msgLen)),
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  Block encrypt / decrypt
//  Block layout (4096 bytes):
//    [0:32]  ephemeral X25519 pub (direct) or random salt (channel)
//    [32:56] XChaCha20 nonce
//    [56:]   ciphertext + 16-byte Poly1305 tag
// ═══════════════════════════════════════════════════════════════════════

async function encryptDirect(recipientEdPubBase64, plainBytes) {
  const x25519Bytes = edPubToX25519Bytes(b64dec(recipientEdPubBase64));
  const ephKP  = await genX25519Keypair();
  const ephPub = await exportPubRaw(ephKP.publicKey);
  const shared = await ecdh(ephKP.privateKey, x25519Bytes);
  const key    = await sha256(shared);
  const nonce  = crypto.getRandomValues(new Uint8Array(24));
  const sealed = xchacha20Seal(key, nonce, plainBytes);
  const payload = new Uint8Array(4096);
  payload.set(ephPub, 0); payload.set(nonce, 32); payload.set(sealed, 56);
  return payload;
}

async function encryptChannelRaw(channelKey32, plainBytes) {
  const salt   = crypto.getRandomValues(new Uint8Array(32));
  const catted = new Uint8Array(64);
  catted.set(channelKey32); catted.set(salt, 32);
  const blockKey = await sha256(catted);
  const nonce    = crypto.getRandomValues(new Uint8Array(24));
  const sealed   = xchacha20Seal(blockKey, nonce, plainBytes);
  const payload  = new Uint8Array(4096);
  payload.set(salt, 0); payload.set(nonce, 32); payload.set(sealed, 56);
  return payload;
}

async function tryDecryptDirect(edPrivJWK, payloadBytes) {
  try {
    const x25519Priv = await edPrivJWKToX25519PrivKey(edPrivJWK);
    const shared     = await ecdh(x25519Priv, payloadBytes.slice(0, 32));
    const key        = await sha256(shared);
    return xchacha20Open(key, payloadBytes.slice(32, 56), payloadBytes.slice(56));
  } catch { return null; }
}

async function tryDecryptChannel(channelKey32, payloadBytes) {
  try {
    const salt   = payloadBytes.slice(0, 32);
    const catted = new Uint8Array(64);
    catted.set(channelKey32); catted.set(salt, 32);
    const blockKey = await sha256(catted);
    return xchacha20Open(blockKey, payloadBytes.slice(32, 56), payloadBytes.slice(56));
  } catch { return null; }
}

async function passphraseToKey(passphrase) {
  return sha256(new TextEncoder().encode(passphrase));
}

// ═══════════════════════════════════════════════════════════════════════
//  IndexedDB
// ═══════════════════════════════════════════════════════════════════════

let _db = null;
function openDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((res, rej) => {
    const req = indexedDB.open('sneakernet', 2);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('identities')) {
        db.createObjectStore('identities', {keyPath:'name'});
      }
    };
    req.onsuccess = e => { _db=e.target.result; res(_db); };
    req.onerror   = e => rej(e.target.error);
  });
}

async function dbGetAll(store) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction(store,'readonly').objectStore(store).getAll();
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  });
}

async function dbPut(store, obj) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction(store,'readwrite').objectStore(store).put(obj);
    req.onsuccess = () => res();
    req.onerror   = e => rej(e.target.error);
  });
}

async function dbDelete(store, key) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction(store,'readwrite').objectStore(store).delete(key);
    req.onsuccess = () => res();
    req.onerror   = e => rej(e.target.error);
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  BrowserBackend
//
//  Implements the same interface as ServerBackend but runs all crypto
//  in-browser. Keys live in IndexedDB. Contacts and channels in
//  localStorage. Messages are held in memory and cleared on reload.
// ═══════════════════════════════════════════════════════════════════════

class BrowserBackend {
  constructor() {
    this._inbox   = [];  // decrypted messages, server-compatible shape
    this._nextId  = 0;
    this._resumeToken = localStorage.getItem('snk_resume_token') || '';
    this._loadSentIntoInbox();  // hydrate sent messages before first getMessages() call
  }

  get requiresAuth() { return false; }
  async isAuthenticated() { return true; }
  async createKeystore() {}
  async unlock() {}
  async lock() {}

  // ── identities ──────────────────────────────────────────────────────────
  // IndexedDB record (v2): {name, pubBase64(Ed25519), privJWK(Ed25519)}
  // Old records (v1) have {name, pubBase64(X25519), privJWK(X25519),
  //   signingPubBase64(Ed25519), signingPrivJWK(Ed25519)}.
  // Migration: prefer signingPubBase64/signingPrivJWK when present.
  // Returned shape: {name, public_key(Ed25519)}

  _edPubB64(id)  { return id.signingPubBase64  || id.pubBase64;  }
  _edPrivJWK(id) { return id.signingPrivJWK    || id.privJWK;    }

  async listIdentities() {
    const ids = await dbGetAll('identities');
    return ids.map(id => ({
      name:       id.name,
      public_key: this._edPubB64(id),
    }));
  }

  async addIdentity(name) {
    const ids = await dbGetAll('identities');
    if (ids.find(i => i.name === name)) throw new Error('duplicate');

    const kp      = await genEd25519Keypair();
    const pubBytes = await exportEd25519PubRaw(kp.publicKey);
    const privJWK  = await exportEd25519PrivJWK(kp.privateKey);

    await dbPut('identities', {
      name,
      pubBase64: b64enc(pubBytes),
      privJWK,
    });
  }

  async deleteIdentity(name) {
    await dbDelete('identities', name);
  }

  // ── contacts ────────────────────────────────────────────────────────────
  // localStorage (v2): [{name, public_key(Ed25519)}]
  // Old format had {name, public_key(X25519), signing_public_key(Ed25519)}.
  // Migration: if signing_public_key is present, use it as the unified key.

  _loadContacts() {
    try {
      const raw = JSON.parse(localStorage.getItem('snk_contacts') || '[]');
      return raw.map(c => ({
        name:       c.name,
        public_key: c.signing_public_key || c.public_key || c.publicKey || '',
      }));
    } catch { return []; }
  }

  _saveContacts(arr) { localStorage.setItem('snk_contacts', JSON.stringify(arr)); }

  async listContacts() { return this._loadContacts(); }

  async addContact(name, public_key) {
    const cs = this._loadContacts();
    if (cs.find(c => c.public_key === public_key)) throw new Error('duplicate');
    cs.push({name, public_key});
    this._saveContacts(cs);
  }

  async removeContact(pubKeyB64url) {
    const pubKey = fromB64url(pubKeyB64url);
    const cs = this._loadContacts().filter(c => c.public_key !== pubKey);
    this._saveContacts(cs);
  }

  async renameContact(pubKeyB64url, newName) {
    const pubKey = fromB64url(pubKeyB64url);
    const cs = this._loadContacts();
    const c = cs.find(c => c.public_key === pubKey);
    if (!c) throw new Error('not found');
    c.name = newName;
    this._saveContacts(cs);
  }

  // ── channels ────────────────────────────────────────────────────────────
  // localStorage: [{name, keyBase64}]

  _loadChannels() {
    try { return JSON.parse(localStorage.getItem('snk_channels') || '[]'); }
    catch { return []; }
  }
  _saveChannels(arr) { localStorage.setItem('snk_channels', JSON.stringify(arr)); }

  async listChannels() {
    return this._loadChannels().map(ch => ({name: ch.name}));
  }

  async joinChannel(name, passphrase) {
    const chs = this._loadChannels();
    if (chs.find(c => c.name === name)) throw new Error('duplicate');
    const keyBytes = await passphraseToKey(passphrase);
    chs.push({name, keyBase64: b64enc(keyBytes)});
    this._saveChannels(chs);
  }

  async leaveChannel(name) {
    this._saveChannels(this._loadChannels().filter(c => c.name !== name));
  }

  // ── scrape ──────────────────────────────────────────────────────────────
  // Fetches raw blocks from /api/blocks, decrypts against all local
  // identities and channels, stores results in _inbox.

  async scrape() {
    this._loadSentIntoInbox();

    const ids      = await dbGetAll('identities');
    const channels = this._loadChannels();
    const chKeys   = channels.map(ch => ({name: ch.name, key: b64dec(ch.keyBase64)}));

    // Only seed seenIds from received blocks, not sent-log entries.
    // Sent-log entries must not block decryption of those same blocks by recipient identities.
    const seenIds  = new Set(this._inbox.filter(m => !m.sent_to).map(m => m.block_id));
    let found = 0;
    let pageToken = this._resumeToken;
    let latestResumeToken = this._resumeToken;
    const defaultSince = Math.floor(Date.now() / 1000) - 7 * 24 * 3600;

    do {
      const params = new URLSearchParams({limit: 200});
      if (pageToken) {
        params.set('page_token', pageToken);
      } else {
        params.set('since', defaultSince);
      }
      const r = await fetch('/api/blocks?' + params);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      if (data.resume_token) latestResumeToken = data.resume_token;
      pageToken = data.next_page_token || '';

      for (const blk of (data.blocks || [])) {
        const payloadBytes = b64dec(blk.payload);
        const blkId = await sha256hex(payloadBytes);
        if (seenIds.has(blkId)) continue;

        let matched = false;

        // Try direct identity decryption
        for (const id of ids) {
          const plain = await tryDecryptDirect(this._edPrivJWK(id), payloadBytes);
          if (plain === null) continue;
          const parsed = readV2PlainFull(plain) || readV1Plain(plain);
          if (!parsed) continue;
          // For a self-send (same identity sent and receives), the sent-log entry is
          // sufficient — skip adding a duplicate received entry.
          const alreadySent = this._inbox.some(
            m => m.block_id === blkId && m.sent_to && m.decrypted_by === id.name
          );
          if (!alreadySent) {
            this._inbox.push({
              id:           ++this._nextId,
              block_id:     blkId,
              channel:      null,
              sender_pub:   parsed.senderPub,
              msg_type:     parsed.msgType,
              content:      parsed.contentB64,
              thread_refs:  parsed.threadRefs,
              sent_at:      parsed.sentAt,
              received_at:  new Date().toISOString(),
              decrypted_by: id.name,
            });
            found++;
          }
          seenIds.add(blkId);
          matched = true; break;
        }

        // Try channel decryption
        if (!matched) {
          for (const ch of chKeys) {
            const plain = await tryDecryptChannel(ch.key, payloadBytes);
            if (plain === null) continue;
            const parsed = readV2PlainFull(plain) || readV1Plain(plain);
            if (!parsed) continue;
            this._inbox.push({
              id:          ++this._nextId,
              block_id:    blkId,
              channel:     ch.name,
              sender_pub:  parsed.senderPub,
              msg_type:    parsed.msgType,
              content:     parsed.contentB64,
              thread_refs: parsed.threadRefs,
              sent_at:     parsed.sentAt,
              received_at: new Date().toISOString(),
            });
            seenIds.add(blkId);
            found++; break;
          }
        }
      }
    } while (pageToken);

    this._resumeToken = latestResumeToken;
    if (latestResumeToken) localStorage.setItem('snk_resume_token', latestResumeToken);
    return {found};
  }

  async getMessages(afterId) {
    return this._inbox.filter(m => m.id > afterId);
  }

  // ── send ────────────────────────────────────────────────────────────────

  async _getSenderKeys(senderIdentityName) {
    if (!senderIdentityName) return {senderPubBytes: null, signingPrivKey: null};
    const ids = await dbGetAll('identities');
    const id  = ids.find(i => i.name === senderIdentityName);
    if (!id) return {senderPubBytes: null, signingPrivKey: null};
    return {
      senderPubBytes: b64dec(this._edPubB64(id)),
      signingPrivKey: await importEd25519PrivJWK(this._edPrivJWK(id)),
    };
  }

  async _getPowFloor() {
    try {
      const r = await fetch('/v1/pow-limit');
      if (!r.ok) return 0;
      const d = await r.json();
      return d.pow_floor || 0;
    } catch { return 0; }
  }

  // Create a short-lived Web Worker that importScripts argon2 from the relay
  // and mines a stamp off the main thread.
  _makePoWWorker() {
    const argon2Url = new URL('/argon2.js', location.href).href;
    const src = `
importScripts(${JSON.stringify(argon2Url)});
const _salt = new TextEncoder().encode('sneakernet-pow-v1');
function _lz(h) {
  let n = 0;
  for (const b of h) {
    if (b === 0) { n += 8; continue; }
    let m = 0x80;
    while (m && !(b & m)) { n++; m >>>= 1; }
    break;
  }
  return n;
}
self.onmessage = async function(e) {
  const {payload, target} = e.data;
  if (target <= 0) { self.postMessage({stamp:[0,0,0,0], workFactor:0}); return; }
  const input = new Uint8Array(4100);
  input.set(new Uint8Array(payload), 4);
  try {
    while (true) {
      crypto.getRandomValues(input.subarray(0, 4));
      const r = await argon2.hash({
        pass: input, salt: _salt,
        time: 1, mem: 65536, parallelism: 1, hashLen: 32,
        type: argon2.ArgonType.Argon2id,
      });
      const wf = _lz(r.hash);
      if (wf >= target) {
        self.postMessage({stamp: Array.from(input.subarray(0,4)), workFactor: wf});
        return;
      }
    }
  } catch { self.postMessage({stamp:[0,0,0,0], workFactor:0}); }
};`;
    return new Worker(URL.createObjectURL(new Blob([src], {type:'application/javascript'})));
  }

  // Mine a stamp for payload in a Worker. Falls back to zero stamp on error.
  async _mineStamp(payload) {
    try {
      const floor = await this._getPowFloor();
      if (floor <= 0) return new Uint8Array(4);
      return await new Promise(resolve => {
        const w = this._makePoWWorker();
        w.onmessage = e => { w.terminate(); resolve(new Uint8Array(e.data.stamp)); };
        w.onerror   = () => { w.terminate(); resolve(new Uint8Array(4)); };
        w.postMessage({payload: payload.slice(), target: floor});
      });
    } catch { return new Uint8Array(4); }
  }

  async _postBlock(payload) {
    const stamp = await this._mineStamp(payload);
    const r = await fetch('/api/blocks', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({stamp: b64enc(stamp), payload: b64enc(payload)}),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.error || `HTTP ${r.status}`);
    }
  }

  // Boost a message by mining a better stamp. Returns new work_factor or null.
  // Hard 5-second budget; terminates the worker if no improvement is found in time.
  async boost(blockId) {
    const br = await fetch(`/api/blocks/${blockId}`);
    if (!br.ok) return null;
    const bd = await br.json();
    const payload = b64dec(bd.payload);
    const currentWF = bd.work_factor || 0;

    const w = this._makePoWWorker();
    let result = null;
    try {
      result = await Promise.race([
        new Promise(resolve => {
          w.onmessage = e => resolve(e.data);
          w.onerror   = ()  => resolve(null);
          w.postMessage({payload: payload.slice(), target: currentWF + 1});
        }),
        new Promise(resolve => setTimeout(() => resolve(null), 5000)),
      ]);
    } finally {
      w.terminate();
    }

    if (!result || result.workFactor <= currentWF) return null;
    const stamp = new Uint8Array(result.stamp);
    const sr = await fetch('/api/blocks', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({stamp: b64enc(stamp), payload: b64enc(payload)}),
    });
    if (!sr.ok) return null;
    return result.workFactor;
  }

  // ── sent log (localStorage) ─────────────────────────────────────────
  _loadSentLog() {
    try { return JSON.parse(localStorage.getItem('snk_sent') || '[]'); } catch { return []; }
  }
  _saveSentLog(log) { localStorage.setItem('snk_sent', JSON.stringify(log)); }

  _addSentRecord(rec) {
    const log = this._loadSentLog();
    log.push(rec);
    this._saveSentLog(log);
  }

  // Hydrate inbox from the persisted sent log (called at start of scrape).
  _loadSentIntoInbox() {
    const seenIds = new Set(this._inbox.map(m => m.block_id));
    for (const r of this._loadSentLog()) {
      if (seenIds.has(r.blockId)) continue;
      this._inbox.push({
        id:           ++this._nextId,
        block_id:     r.blockId,
        channel:      null,
        sender_pub:   r.senderSignPub || '',
        msg_type:     0,
        content:      b64enc(new TextEncoder().encode(r.content)),
        thread_refs:  r.threadRefs || Array(8).fill('0'.repeat(64)),
        sent_at:      r.sentAt || r.sent_at || null,
        received_at:  r.sentAt || r.sent_at || null,
        sent_to:      r.recipientPub,
        decrypted_by: r.senderIdentity || '',
        work_factor:  0,
      });
      seenIds.add(r.blockId);
    }
  }

  async sendDirect(recipientPublicKey, message, senderIdentity, replyToBlockId) {
    recipientPublicKey = fromB64url(recipientPublicKey); // normalize: accept standard or URL-safe b64
    const {senderPubBytes, signingPrivKey} = await this._getSenderKeys(senderIdentity);
    const threadRefs = replyToBlockId
      ? [replyToBlockId, ...Array(7).fill('0'.repeat(64))]
      : null;
    const plain   = await buildV2Plain(message, senderPubBytes, signingPrivKey, threadRefs);
    const payload = await encryptDirect(recipientPublicKey, plain);
    const blockId = await sha256hex(payload);
    await this._postBlock(payload);

    const sentAt = new Date().toISOString();
    const rec = {
      blockId,
      recipientPub:   recipientPublicKey,
      senderSignPub:  senderPubBytes ? b64enc(senderPubBytes) : '',
      senderIdentity: senderIdentity || '',
      content:        message,
      sentAt,
      threadRefs:     threadRefs || null,
    };
    this._addSentRecord(rec);
    this._inbox.push({
      id:           ++this._nextId,
      block_id:     blockId,
      channel:      null,
      sender_pub:   rec.senderSignPub,
      msg_type:     0,
      content:      b64enc(new TextEncoder().encode(message)),
      thread_refs:  threadRefs || Array(8).fill('0'.repeat(64)),
      sent_at:      sentAt,
      received_at:  sentAt,
      sent_to:      recipientPublicKey,
      decrypted_by: senderIdentity || '',
      work_factor:  0,
    });
    return {blockId};
  }

  async sendChannel(channelName, message, senderIdentity, replyToBlockId) {
    const chs = this._loadChannels();
    const ch  = chs.find(c => c.name === channelName);
    if (!ch) throw new Error('channel not found');
    const {senderPubBytes, signingPrivKey} = await this._getSenderKeys(senderIdentity);
    const threadRefs = replyToBlockId
      ? [replyToBlockId, ...Array(7).fill('0'.repeat(64))]
      : null;
    const plain   = await buildV2Plain(message, senderPubBytes, signingPrivKey, threadRefs);
    const payload = await encryptChannelRaw(b64dec(ch.keyBase64), plain);
    const blockId = await sha256hex(payload);
    await this._postBlock(payload);
    const sentAt = new Date().toISOString();
    this._inbox.push({
      id:           ++this._nextId,
      block_id:     blockId,
      channel:      channelName,
      sender_pub:   senderPubBytes ? b64enc(senderPubBytes) : '',
      msg_type:     0,
      content:      b64enc(new TextEncoder().encode(message)),
      thread_refs:  threadRefs || Array(8).fill('0'.repeat(64)),
      sent_at:      sentAt,
      received_at:  sentAt,
      sent_to:      null,
      decrypted_by: senderIdentity || '',
      work_factor:  0,
    });
    return {blockId};
  }
}

const backend = new BrowserBackend();

const UI_CONFIG = {
  pageTitle:       'Browser',
  lockSubtitle:    'Browser — client-side crypto, keys in IndexedDB',
  sidebarSubtitle: 'Browser',
  hasLockButton:   false,
  identitiesHint:  'Keys generated in your browser, stored in IndexedDB. Share your <strong>public key</strong> so others can send you messages and verify your identity — one key does both. Keys never leave this browser.',
  sendStatusMsg:   'Block stored on relay.',
  welcomeHtml: `<div style="max-width:520px;text-align:left">
    <p style="margin-bottom:18px;font-size:15px;color:var(--text)">Select a conversation from the sidebar, or click <strong>+</strong> to send a new message.</p>
    <div style="font-size:13px;color:var(--muted);line-height:1.65;background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent-line);border-radius:6px;padding:14px 16px">
      <strong style="color:var(--text);display:block;margin-bottom:8px">You are using the browser client.</strong>
      <strong style="color:var(--text)">Message lifetime scales with proof-of-work.</strong> When you send, your browser mines PoW locally — this may take a few seconds but extends your block's TTL beyond the 24-hour base.<br><br>
      <strong style="color:var(--text)">Your inbox is not saved.</strong> Decrypted messages live in memory and are cleared when you close or reload this tab. Re-scanning will only recover blocks still held by the relay.<br><br>
      <strong style="color:var(--text)">Keys are stored in this browser only.</strong> Your identities live in this browser's IndexedDB. A different browser, incognito window, or clearing browser data means starting over with a new identity.
    </div>
    <div style="margin-top:16px">
      <button class="sm ghost" data-join-channel="sneakernet-alpha">#sneakernet-alpha &rarr;</button>
    </div>
  </div>`,
};

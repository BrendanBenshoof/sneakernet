// ── ServerBackend ──────────────────────────────────────────────────────────
// Wraps the local node REST API. Swap for BrowserBackend to run all crypto
// in-browser with no local node (see transport/relay/ui/app.html).
class ServerBackend {
  constructor() {
    this._token = sessionStorage.getItem('snk_token');
  }

  get requiresAuth() { return true; }

  _hdrs(withBody = false) {
    const h = {};
    if (this._token) h['Authorization'] = 'Bearer ' + this._token;
    if (withBody) h['Content-Type'] = 'application/json';
    return h;
  }

  async _req(method, path, body) {
    const r = await fetch(path, {
      method,
      headers: this._hdrs(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (r.status === 401) {
      this._token = null;
      sessionStorage.removeItem('snk_token');
      showLock();
      lockErr('Session expired — please unlock again.');
      return null;
    }
    return r;
  }

  async isAuthenticated() {
    if (!this._token) return false;
    const r = await fetch('/api/identities', {headers: this._hdrs()});
    return r.ok;
  }

  async createKeystore(password) {
    const r = await this._req('POST', '/api/keystore/create', {password});
    if (!r) throw new Error('failed');
    if (r.status === 409) throw new Error('exists');
    if (!r.ok) throw new Error('failed');
  }

  async unlock(password) {
    const r = await this._req('POST', '/api/unlock', {password});
    if (!r) throw new Error('failed');
    if (r.status === 404) throw new Error('noKeystore');
    if (!r.ok) throw new Error('wrongPassword');
    const data = await r.json();
    this._token = data.token;
    sessionStorage.setItem('snk_token', this._token);
  }

  async lock() {
    await this._req('POST', '/api/lock');
    this._token = null;
    sessionStorage.removeItem('snk_token');
  }

  async listIdentities() {
    const r = await this._req('GET', '/api/identities');
    if (!r || !r.ok) return [];
    return await r.json() || [];
  }

  async addIdentity(name) {
    const r = await this._req('POST', '/api/identities', {name});
    if (!r) throw new Error('failed');
    if (r.status === 409) throw new Error('duplicate');
    if (!r.ok) throw new Error('failed');
  }

  async deleteIdentity(name) {
    const r = await this._req('DELETE', `/api/identities/${encodeURIComponent(name)}`);
    if (!r || !r.ok) throw new Error('failed');
  }

  async mineIdentityPow(name) {
    const r = await this._req('POST', `/api/identities/${encodeURIComponent(name)}/mine-pow`);
    if (!r) throw new Error('cancelled');
    if (!r.ok) { const d = await r.json(); throw new Error(d.error || 'failed'); }
    return await r.json(); // {pow_stamp, pow_bits}
  }

  async listContacts() {
    const r = await this._req('GET', '/api/contacts');
    if (!r || !r.ok) return [];
    return await r.json() || [];
  }

  async addContact(name, public_key) {
    const r = await this._req('POST', '/api/contacts', {name, public_key});
    if (!r) throw new Error('failed');
    if (r.status === 409) throw new Error('duplicate');
    if (!r.ok) throw new Error('failed');
  }

  async removeContact(pubKeyB64url) {
    const r = await this._req('DELETE', `/api/contacts/${encodeURIComponent(pubKeyB64url)}`);
    if (!r || !r.ok) throw new Error('failed');
  }

  async renameContact(pubKeyB64url, newName) {
    const r = await this._req('PATCH', `/api/contacts/${encodeURIComponent(pubKeyB64url)}`, {name: newName});
    if (!r || !r.ok) throw new Error('failed');
  }

  async listChannels() {
    const r = await this._req('GET', '/api/channels');
    if (!r || !r.ok) return [];
    return await r.json() || [];
  }

  async joinChannel(name, passphrase) {
    const r = await this._req('POST', '/api/channels', {name, passphrase});
    if (!r) throw new Error('failed');
    if (r.status === 409) throw new Error('duplicate');
    if (!r.ok) throw new Error('failed');
  }

  async leaveChannel(name) {
    const r = await this._req('DELETE', `/api/channels/${encodeURIComponent(name)}`);
    if (!r || !r.ok) throw new Error('failed');
  }

  async scrape(full = false) {
    const r = await this._req('POST', '/api/scrape', full ? {full: true} : undefined);
    if (!r || !r.ok) throw new Error('failed');
    return await r.json(); // {found: N}
  }

  async getMessages(afterId, wfUpdatedSince = 0) {
    let url = `/api/messages?after_id=${afterId}`;
    if (wfUpdatedSince > 0) url += `&wf_updated_since=${wfUpdatedSince}`;
    const r = await this._req('GET', url);
    if (!r || !r.ok) return [];
    return await r.json() || [];
  }

  async sendDirect(recipientPublicKey, message, senderIdentity, replyToBlockId) {
    const payload = {recipient_public_key: fromB64url(recipientPublicKey), message};
    if (senderIdentity) payload.sender_identity = senderIdentity;
    if (replyToBlockId) payload.reply_to_block_id = replyToBlockId;
    const r = await this._req('POST', '/api/send', payload);
    if (!r) throw new Error('failed');
    if (!r.ok) { const d = await r.json(); throw new Error(d.error || 'failed'); }
    const d = await r.json();
    return {blockId: d.block_ids?.[0] || null};
  }

  async sendChannel(channelName, message, senderIdentity, replyToBlockId) {
    const payload = {channel_name: channelName, message};
    if (senderIdentity) payload.sender_identity = senderIdentity;
    if (replyToBlockId) payload.reply_to_block_id = replyToBlockId;
    const r = await this._req('POST', '/api/send-channel', payload);
    if (!r) throw new Error('failed');
    if (!r.ok) { const d = await r.json(); throw new Error(d.error || 'failed'); }
    const d = await r.json();
    return {blockId: d.block_id || null};
  }

  async sendForum(channelName, message, subject, senderIdentity, replyToBlockId) {
    const payload = {channel_name: channelName, message, forum_post: true};
    if (subject) payload.subject = subject;
    if (senderIdentity) payload.sender_identity = senderIdentity;
    if (replyToBlockId) payload.reply_to_block_id = replyToBlockId;
    const r = await this._req('POST', '/api/send-channel', payload);
    if (!r) throw new Error('failed');
    if (!r.ok) { const d = await r.json(); throw new Error(d.error || 'failed'); }
    const d = await r.json();
    return {blockId: d.block_id || null};
  }

  // Boost a message by mining a better stamp. Returns new work_factor or null.
  async boost(blockId) {
    const r = await this._req('POST', '/api/boost', {block_id: blockId});
    if (!r) return null;
    if (r.status === 504) return 0; // no improvement found — worth retrying
    if (!r.ok) return null;
    const d = await r.json();
    return d.work_factor ?? null;
  }
}

const backend = new ServerBackend();

const UI_CONFIG = {
  pageTitle:       'Local Node',
  lockSubtitle:    'Local Node — server-side crypto, persistent keystore',
  sidebarSubtitle: 'Local Node',
  hasLockButton:   true,
  identitiesHint:  'Stored in the server-side encrypted keystore. Share your <strong>public key</strong> so others can send you messages and verify your identity — one key does both.',
  sendStatusMsg:   'Message stored in blockstore.',
  welcomeHtml:     '<div><p>Select a conversation from the sidebar, or click <strong>+</strong> to send a new message.</p><div style="margin-top:12px"><button class="sm ghost" data-join-forum="sneakernet-alpha">§sneakernet-alpha &rarr;</button></div></div>',
};

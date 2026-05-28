# The web client

Every relay node serves a browser UI at `/app`. You can use it to send and receive messages from any device with a web browser — no installation required.

It is real. The cryptography is correct. It is also the weakest way to use sneakernet, and you should understand why before relying on it for anything sensitive.

---

## What it can do

The web client runs entirely in your browser. It implements the full v2 message format: X25519 key agreement, XChaCha20-Poly1305 encryption, Ed25519 signing, and skip-list threading. No crypto happens on the server. The relay never sees your plaintext.

You can:

- Create identities and receive direct messages
- Join channels via shared passphrase
- Add contacts and send messages to them
- Read threaded conversations

---

## What it cannot do well

### Proof of work

The native node mines a proof-of-work stamp for every block it submits. Higher work means a longer TTL — a block with `work_factor=4` lives five days; `work_factor=8` lives nine. The browser does not mine PoW at all. Every block it submits carries a zero stamp: `work_factor=0`, TTL 24 hours.

Messages sent from the browser disappear from the network within a day. If the recipient does not scrape within that window, the block is gone. A native node or phone app can mine even modest PoW in the background and give your messages a much better chance of surviving long enough to be read.

### Decryption throughput

To check for new messages, the client fetches every recent block from the relay and tries to decrypt each one with every identity and channel key it holds. On a native node this is fast — Go crypto running natively, with the block database local. In the browser, the XChaCha20-Poly1305 implementation is pure JavaScript, and every scrape pulls blocks over HTTP. With many blocks or many keys, each scrape cycle is slow and CPU-intensive. The browser re-scrapes every five seconds, which can visibly tax older or low-power devices.

A dedicated node running on a laptop or server handles this invisibly in the background. A phone app can do the same. The browser client does it in your foreground tab with JavaScript.

---

## What is and is not persisted

| Data | Where stored | Survives reload? | Survives clearing browser data? |
|------|-------------|-----------------|-------------------------------|
| Identity keys | IndexedDB | Yes | No |
| Contacts | localStorage | Yes | No |
| Channel keys | localStorage | Yes | No |
| Decrypted inbox | Memory only | **No** | No |
| Sent message log | localStorage | Yes | No |
| Raw blocks | Never stored | — | — |

**Your inbox does not persist.** Decrypted messages are held in memory and vanish when you close or reload the tab. The next time you open the client it re-scrapes the relay, but blocks that have since expired will not come back. Messages sent to you before you opened the tab may already be gone.

**Your keys are browser-local.** Identities live in IndexedDB for this browser, on this device, at this origin. If you use a different browser, a private/incognito window, or clear your browser storage, those identities are gone. There is no password protection on the browser keystore — the keys sit as plaintext JWK entries in IndexedDB, protected only by the browser's same-origin policy. The native keystore is encrypted with Argon2id + XChaCha20-Poly1305 behind a passphrase; the browser keystore is not.

**The relay only sees opaque blocks.** The server does not store or process your messages. All it does is hold blocks until they expire and serve them to whoever asks. The browser client is fetching those blocks and doing the decryption work itself.

---

## When the browser client is appropriate

Use it when you need to check in from a device you do not control — a borrowed laptop, a library terminal, a phone you do not want to install anything on. It is also a reasonable way to get started before setting up a native node.

For day-to-day use, and especially for anything time-sensitive, a native node or app is much better. It mines real PoW so messages live longer. It decrypts in the background without draining a browser tab. It persists your inbox and keystore properly. The web client is a way to get started and a fallback for devices you do not control, not the intended way to rely on this network.

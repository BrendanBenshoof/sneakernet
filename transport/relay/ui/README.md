# transport/relay/ui

`app.html` is **generated** — do not edit it directly.

## How to make changes

All UI lives in `ui/template.html` at the repo root. Backend-specific behaviour lives in `ui/injection-browser.js`. After editing either, regenerate:

```
python3 ui/generate.py
```

## What varies between this UI and the local-node UI

Everything variant-specific is declared in `UI_CONFIG` inside `ui/injection-browser.js`:

| field | value |
|---|---|
| `pageTitle` | `'Browser'` |
| `lockSubtitle` | client-side crypto / IndexedDB description |
| `sidebarSubtitle` | `'Browser'` |
| `hasLockButton` | `false` — no lock button (no server session to clear) |
| `identitiesHint` | browser / IndexedDB hint text |
| `sendStatusMsg` | `'Block stored on relay.'` |

The local-node UI (`client/api/ui/index.html`) is generated from the same template using `ui/injection-server.js`, which delegates all crypto and key storage to the local node's REST API via `ServerBackend`.

## Crypto

`injection-browser.js` includes a self-contained XChaCha20-Poly1305 implementation, Web Crypto helpers (X25519, Ed25519, SHA-256), the v2 message format, and `BrowserBackend` — all run client-side with keys stored in IndexedDB.

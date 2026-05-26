# client/api

HTTP API server for the sneakernet client. Routes are registered in `server.go`; handlers live in `handlers.go`.

## ⚠ Keep BrowserBackend in sync

`BrowserBackend` in `ui/injection-browser.js` reimplements this API's behaviour in JavaScript for the relay web UI. Any change here that affects the browser UI **must** be mirrored there.

Routes currently consumed by `BrowserBackend`:

| Method | Path | BrowserBackend method |
|---|---|---|
| `POST` | `/api/blocks` | `_postBlock` |
| `GET` | `/api/blocks` | `scrape` |
| `GET` | `/api/identities` | `listIdentities` |
| `POST` | `/api/identities` | `addIdentity` |
| `DELETE` | `/api/identities/{name}` | `deleteIdentity` |
| `GET` | `/api/contacts` | `listContacts` |
| `POST` | `/api/contacts` | `addContact` |
| `DELETE` | `/api/contacts/{pub_key}` | `removeContact` |
| `PATCH` | `/api/contacts/{pub_key}` | `renameContact` |
| `GET` | `/api/channels` | `listChannels` |
| `POST` | `/api/channels` | `joinChannel` |
| `DELETE` | `/api/channels/{name}` | `leaveChannel` |

`BrowserBackend` does **not** call `/api/unlock`, `/api/lock`, `/api/scrape`, `/api/send`, or `/api/send-channel` — it handles auth, scraping, and sending entirely in-browser.

Routes only used by `ServerBackend` (the local-node web UI and mobile clients) do not need a JS counterpart.

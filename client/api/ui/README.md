# client/api/ui

`index.html` is **generated** — do not edit it directly.

## How to make changes

All UI lives in `ui/template.html` at the repo root. Backend-specific behaviour lives in `ui/injection-server.js`. After editing either, regenerate:

```
python3 ui/generate.py
```

## What varies between this UI and the relay UI

Everything variant-specific is declared in `UI_CONFIG` inside `ui/injection-server.js`:

| field | value |
|---|---|
| `pageTitle` | `'Local Node'` |
| `lockSubtitle` | server-side keystore description |
| `sidebarSubtitle` | `'Local Node'` |
| `hasLockButton` | `true` — lock button is injected into the sidebar footer |
| `identitiesHint` | server keystore hint text |
| `sendStatusMsg` | `'Message stored in blockstore.'` |

The relay UI (`transport/relay/ui/app.html`) is generated from the same template using `ui/injection-browser.js`, which runs all crypto in-browser via `BrowserBackend`.

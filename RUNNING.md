# Running Sneakernet

## Requirements

- Go 1.25 or later

## Build

```
git clone <repo>
cd sneakernet
go build ./cmd/snk
```

This produces a single `snk` binary.

---

## Run a personal node

A personal node dials relay peers to sync blocks and serves an authenticated local API (keystore, identities, messages).

```
./snk node \
  -api-addr   127.0.0.1:8080 \
  -blocks     blocks.db \
  -messages   messages.db \
  -keystore   keystore.json \
  -peers      https://relay.example.com
```

Open `http://127.0.0.1:8080` in a browser to use the local interface.

**All flags:**

| Flag | Default | Description |
|---|---|---|
| `-api-addr` | `127.0.0.1:8080` | Local API listen address |
| `-blocks` | `blocks.db` | Blockstore directory (BadgerDB) |
| `-messages` | `messages.db` | Message store (SQLite) |
| `-keystore` | `keystore.json` | Keystore file |
| `-peers` | — | Comma-separated relay URLs to sync with |
| `-lan` | off | Scan LAN for sneakernet peers |
| `-usb-dir` | — | Watch this directory for USB volumes to sync |
| `-usb-interval` | `30s` | How often to check the USB directory |
| `-sync-interval` | `5m` | Interval between peer sync rounds |
| `-pow-floor` | `0` | Minimum proof-of-work to accept from peers |
| `-storage-limit` | unlimited | Max blockstore size, e.g. `10GB`, `512MB` |
| `-reserve-physical` | `0` | Storage reserved for physical/local blocks |
| `-reserve-lan` | `0` | Storage reserved for LAN peer blocks |

---

## Run a relay node

A relay is a public server. It accepts inbound block-exchange connections from nodes, peers with other relays, and serves the browser webapp at `/app`.

```
./snk relay \
  -addr          0.0.0.0:8081 \
  -blocks        blocks.db \
  -storage-limit 10GB \
  -peers         https://other-relay.example.com
```

**All flags:**

| Flag | Default | Description |
|---|---|---|
| `-addr` | `0.0.0.0:8081` | Listen address |
| `-blocks` | `blocks.db` | Blockstore directory (BadgerDB) |
| `-peers` | — | Comma-separated peer relay URLs |
| `-lan` | off | Also scan LAN for peers |
| `-sync-interval` | `5m` | Interval between peer sync rounds |
| `-pow-floor` | `0` | Minimum proof-of-work to accept |
| `-storage-limit` | unlimited | Max blockstore size |
| `-reserve-physical` | `0` | Reserved for physical/local blocks |
| `-reserve-lan` | `0` | Reserved for LAN peer blocks |
| `-reserve-regional` | `0` | Reserved for regional relay blocks |
| `-reserve-global` | `0` | Reserved for global relay blocks |
| `-region` | — | ISO 3166 codes this relay serves (e.g. `US-GA,CA`); enables regional tagging |
| `-geoip-db` | `<blocks-dir>/geoip.mmdb` | Path to cache the GeoIP MMDB |
| `-geoip-refresh` | `120h` | How often to refresh the GeoIP database |

**Note on regional tagging:** If `-region` is set, the relay downloads a GeoLite2-City database on first start and uses it to tag blocks by origin region. This lets nodes with limited storage preferentially keep locally-produced blocks.

---

## Sync to a USB volume

Copy blocks to a flat-file directory that can be carried on a USB drive and handed to someone else.

```
./snk mass-storage -from-badger blocks.db -to /mnt/usb/sneakernet
```

A volume synced this way contains a `.sneakernet` marker file. Any node with `-usb-dir` pointing at a parent directory will automatically detect and sync with it when plugged in.

**Flags:**

| Flag | Description |
|---|---|
| `-from-badger <dir>` | Source: BadgerDB blockstore |
| `-from-sqlite <path>` | Source: SQLite blockstore |
| `-to <dir>` | Target flat-file directory (required) |
| `-reindex` | Rebuild the index only, do not copy blocks |

---

## Browser UI

Every relay serves a browser UI at `/app`. It runs the full message format in JavaScript — no installation required, works from any device. Read [web_client.md](web_client.md) for details on what it can and cannot do compared to a native node.

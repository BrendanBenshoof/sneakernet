# sneakernet — Android

The Android app wraps the same Go engine that powers the desktop node in a
Kotlin/Compose shell. The UI is the server-side HTML interface served locally
by the embedded Go HTTP server; the Kotlin layer provides Bluetooth, LAN, and
lifecycle plumbing that the Go standard library can't reach on Android.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  Kotlin shell (Jetpack Compose)             │
│  • SneakernetApp — Application lifecycle   │
│  • SneakernetSyncService — foreground svc  │
│  • WebViewScreen — loads 127.0.0.1:8080    │
│  • SetupScreen — first-run wizard          │
└────────────────┬────────────────────────────┘
                 │ gomobile-generated JNI bindings
┌────────────────▼────────────────────────────┐
│  Go engine  (mobile/)                       │
│  • blockstore  (BadgerDB)                  │
│  • message store  (SQLite)                 │
│  • relay HTTP client / LAN relay server    │
│  • Bluetooth session handler               │
│  • API server  →  127.0.0.1:8080          │
└─────────────────────────────────────────────┘
```

The Go engine is compiled to an AAR with `gomobile bind` and checked into
`app/libs/mobile.aar` by the build script. The Kotlin code only touches the
engine through the generated Java API in `com.sneakernet.engine.mobile.*`.

### Ports and addresses

| Purpose | Address |
|---|---|
| Local API / WebView origin | `127.0.0.1:8080` |
| LAN relay (peer-to-peer) | `0.0.0.0:14786` |

The API server is bound to loopback only — it exposes the private messaging
API and must never be accessible from the network. The LAN relay is bound to
all interfaces so other nodes on the same network can sync with it.

### Data layout

All persistent data lives under `Context.getFilesDir()`:

```
files/
  blocks.db/      — BadgerDB blockstore
  messages.db     — SQLite message index and scrape checkpoint
  peers.json      — tracked relay peer list
  keystore.json   — encrypted identity and channel keys
  .storage_quota  — sparse balloon file that makes the OS storage reporter
                    show the full reserved budget from day one
```

### Sync transport tiers

`SneakernetSyncService` runs three independent sync mechanisms in parallel:

1. **Relay (HTTP)** — picks the least-recently-synced peer every 5 minutes,
   runs a pull → gossip → push cycle over plain HTTP.
2. **LAN discovery** — mDNS-style UDP scan every 5 minutes; discovered peers
   are added automatically and served by the embedded LAN relay.
3. **Bluetooth Classic (RFCOMM)** — BLE advertising + scanning finds nearby
   sneakernet nodes; an RFCOMM session exchanges blocks directly, no internet
   needed.

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go toolchain | 1.25+ | `go env GOPATH` must resolve |
| gomobile | latest | installed automatically by the build script if absent |
| Android SDK | compileSdk 35 | `$ANDROID_SDK_HOME` or `~/Android/Sdk` |
| Android NDK | 27.x | picked automatically from the SDK's `ndk/` directory |
| Java | 17+ | `$JAVA_HOME` or `java` on `PATH` |

The minimum supported Android version is **API 31 (Android 12)**, required
for the modern Bluetooth permission model (`BLUETOOTH_CONNECT` /
`BLUETOOTH_SCAN` / `BLUETOOTH_ADVERTISE`).

---

## Building

From the repository root:

```sh
# Build both the Go AAR and the debug APK (full rebuild)
./scripts/build-android.sh

# Rebuild the Go AAR only (after changing anything in mobile/ or its deps)
./scripts/build-android.sh --aar

# Rebuild the APK only (after changing Kotlin/XML/res only)
./scripts/build-android.sh --apk
```

The script:
1. Locates the NDK and Java automatically if environment variables are unset.
2. Ensures `gomobile` is on `PATH` (installs it via `go install` if needed).
3. Runs `gomobile bind` targeting `./mobile/` → `android/app/libs/mobile.aar`.
4. Invokes Gradle `assembleDebug`.

The output APK is at `android/app/build/outputs/apk/debug/app-debug.apk`.

### When to rebuild the AAR vs the APK

Changes to anything in `mobile/`, `blockstore/`, `client/`, `transport/`, or
their transitive Go dependencies require `--aar` (or a full rebuild). Changes
to Kotlin source, layout XML, string resources, or drawable assets only
require `--apk`.

---

## Go mobile engine (`mobile/`)

### `Engine`

Created once per process via `NewEngine(dataDir string)`. The Kotlin
`Application` class holds the single instance for the process lifetime.

Key methods exposed to Kotlin:

| Method | Purpose |
|---|---|
| `ConfigureStorage(limit, physReserve, btReserve int64)` | Set storage budget and start the quota balloon goroutine |
| `StartAPIServer(addr, keystorePath string)` | Start the local HTTP API on `addr` (always `127.0.0.1:8080`) |
| `StartSync(intervalSecs int)` | Start the relay sync loop (5-minute interval) |
| `SyncNow()` | Trigger an immediate sync round outside the normal interval |
| `StartLANDiscovery(intervalSecs int)` | Periodically scan for LAN relay peers |
| `StartLANServer()` | Start the LAN relay server on port 14786 |
| `RunBluetoothSession(peer BluetoothPeer)` | Run a full block-exchange over an open RFCOMM socket |
| `AddPeer(url string) bool` | Add a relay peer URL manually |
| `DiskUsageBytes() int64` | Current BadgerDB on-disk size (excludes the quota balloon) |

### Storage tiers and eviction

Blocks are tagged at ingest time:

| Tag | Source | Evicted first? |
|---|---|---|
| `TagPhysical` | Locally authored messages | Last |
| `TagBluetooth` | Received over Bluetooth | Middle |
| `TagLan` | Received from LAN peers | Middle |
| `TagRelay` | Pulled from internet relays | First |

`ConfigureStorage` accepts per-tier reservations. During eviction, the tag
furthest above its reservation loses blocks first; within a tag, lowest
work-factor blocks are evicted first.

**BadgerDB vlog sizing note:** the blockstore opens BadgerDB with
`ValueLogFileSize = 64 MiB` (rather than the 1 GiB default). The default
pre-allocates the full vlog file on the first write, which on Android's f2fs
filesystem immediately consumes the user's entire storage budget before any
real data is stored, triggering constant eviction. The 64 MiB cap keeps
overhead proportional to actual content.

### Bluetooth interface

`RunBluetoothSession` accepts any object implementing `BluetoothPeer`:

```kotlin
interface BluetoothPeer {
    fun read(b: ByteArray): Int   // fills b, returns bytes read
    fun write(b: ByteArray)       // writes all of b or throws
    fun close()
}
```

`SocketPeer` in `com.sneakernet.bluetooth` wraps an Android `BluetoothSocket`
to satisfy this interface.

---

## Kotlin shell

### `SneakernetApp` (Application)

Initialises the engine at process start, applies the stored storage limit if
setup has been completed, and starts the foreground sync service. The engine
instance is accessible to any component via
`(context.applicationContext as SneakernetApp).engine`.

### `SneakernetSyncService` (foreground service)

Persistent foreground service that keeps all sync transports running:

- Calls `Engine.startSync` and `Engine.startLANDiscovery` on `onCreate`.
- Starts the RFCOMM server socket and BLE advertiser/scanner when Bluetooth
  permissions are available (granted during setup or later via `ACTION_ENABLE_BT`).
- `BootReceiver` restarts the service after device reboot so sync continues
  without the user needing to open the app.

Bluetooth session cooldown is 60 seconds per peer address to prevent
immediate reconnects after a session ends.

### `SetupScreen` (first-run wizard)

Two-page Compose wizard shown once, before the WebView:

1. **Bluetooth access** — requests `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN`,
   `BLUETOOTH_ADVERTISE`. Skippable; Bluetooth sync is simply unavailable
   until granted.
2. **Storage budget** — slider from 64 MB to 8 GB (default 1 GB). Calls
   `Engine.configureStorage` immediately so the quota balloon is sized before
   any blocks arrive.

Completion is persisted in `SharedPreferences` (`sneakernet_storage` →
`setup_complete`). The chosen limit is stored in the same prefs file and
reapplied on every engine init.

### `WebViewScreen`

Loads `http://127.0.0.1:8080/` in a full-screen `WebView`. Chrome remote
debugging is enabled (`WebView.setWebContentsDebuggingEnabled(true)`) so you
can inspect the embedded UI from a desktop Chrome instance at
`chrome://inspect`.

A small JS snippet is injected after each page load to force `body` and
`documentElement` height from `window.innerHeight`, working around a WebView
quirk where `vh` units resolve to 0 before the view has its final size.

---

## Permissions

| Permission | Why |
|---|---|
| `BLUETOOTH_CONNECT` | Open RFCOMM sockets to peer devices |
| `BLUETOOTH_SCAN` | Discover nearby BLE-advertising peers |
| `BLUETOOTH_ADVERTISE` | Make this device visible to peers |
| `FOREGROUND_SERVICE` | Keep the sync service alive |
| `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Required foreground type for RFCOMM (API 34+) |
| `FOREGROUND_SERVICE_DATA_SYNC` | Required foreground type for relay/LAN sync (API 34+) |
| `INTERNET` | Reach internet relay peers |
| `RECEIVE_BOOT_COMPLETED` | Restart sync service after reboot |

Bluetooth hardware is declared `required="false"` — the app runs on devices
without Bluetooth; only the Bluetooth sync transport is unavailable.

---

## Inspecting a running app

**Chrome DevTools (WebView UI):** connect a USB cable, enable USB debugging on
the device, open `chrome://inspect` on a desktop Chrome. The sneakernet
WebView appears under the device; you can inspect the DOM, run JS in the
console, and watch network requests to `127.0.0.1:8080`.

**Go logs:** `adb logcat -s SneakernetApp SneakernetSyncService` shows engine
startup, sync round results (pulled/pushed block counts), peer errors, and
Bluetooth session events.

**Status bar (in-app):** the bottom bar of the WebView UI shows the current
blockstore size, time since last sync, blocks pulled and pushed in the last
round, and any peer error.

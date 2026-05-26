# Blockstore Design

The blockstore is the local persistence layer for the sneakernet node. It stores, indexes, and expires opaque message blocks that are exchanged via epidemic routing.

## Block format

A block has two parts stored together but treated differently:

| Field   | Size    | Description |
|---------|---------|-------------|
| Stamp   | 4 bytes | Proof-of-work nonce |
| Payload | 4096 bytes | Opaque application data |

The **block ID** is `sha256(payload)` — the stamp is not part of the identity. Two blocks with the same payload but different stamps are the same block.

Block size is a compile-time constant (`PayloadSize = 4096`). Message framing and multi-block assembly are client-layer concerns; the blockstore is payload-agnostic.

## Proof of work

Work is measured by running argon2id over the concatenated stamp and payload:

```
work_factor = leading_zero_bits(argon2id(stamp ‖ payload))
```

Argon2 parameters (defined in `pow.go`):
- Time: 1 pass
- Memory: 64 MB
- Threads: 1
- Key length: 32 bytes
- Salt: fixed application constant `"sneakernet-pow-v1"`

A higher `work_factor` means more attempts were needed to find the stamp, so higher-PoW blocks are considered more valuable and receive longer storage lifetimes.

## TTL and expiry

Every block gets a computed `expires_at` at insert time:

```
TTL = BaseTTL × (work_factor + 1)
BaseTTL = 24 hours
```

This is linear — a block with `work_factor=0` lives 24 hours, `work_factor=4` lives 5 days, etc. The formula lives in `TTLFromWorkFactor` and is easy to change.

Expired blocks are not returned by any read API. `Prune()` reclaims their disk space.

## Origin tags

Every block carries a `Tag` that records where it was received from:

| Tag | Value | Meaning |
|-----|-------|---------|
| `TagPhysical` | 0 | Physical sneakernet (USB, QR code, locally authored messages) |
| `TagLan` | 1 | Same local network peer |
| `TagRegional` | 2 | Regional peer |
| `TagGlobal` | 3 | Internet relay |

Tags are set by the transport layer at `Put` time. The networking layer is responsible for assigning the correct tag; until it does, all callers default to `TagPhysical`.

Tags drive the eviction policy (see below) but are otherwise opaque to the blockstore. They are stored in both the block value and the traversal index entry so they are available during eviction scans without loading full payloads.

## Storage limits and eviction

The BadgerDB backend supports a configurable total storage limit and per-tag reservations. These are set at startup via the builder methods on `*BadgerStore`:

```go
bs.WithStorageLimit(10 << 30).           // 10 GiB total
  WithReservations(map[Tag]int64{
    TagPhysical: 2 << 30,                // 2 GiB guaranteed for local/physical
    TagLan:      2 << 30,
    TagRegional: 2 << 30,
    TagGlobal:   2 << 30,
  })
```

The `snk relay` command exposes these as CLI flags:

```
-storage-limit 10GB
-reserve-physical 2GB
-reserve-lan 2GB
-reserve-regional 2GB
-reserve-global 2GB
```

Accepted suffixes: `KB`, `MB`, `GB`, `TB` (case-insensitive) or a bare byte count. `0` (the default) means no limit / no reservation.

### Eviction policy

Eviction is triggered reactively inside `Put` whenever `db.Size()` exceeds the configured limit. The node never evicts proactively — storage stays full. `Evict(n)` can also be called explicitly.

At each step the algorithm picks the tag most over its reservation:

```
over[T] = bytes_used[T] − reservation[T]
target  = argmax_T(over[T])   (skipping tags with no remaining blocks)
```

Within the chosen tag, the block with the earliest `ExpiresAt` is removed first — it was going to leave soonest anyway. This continues until `n` blocks have been evicted or nothing remains.

If all tags are within their reservations (e.g. because reservations exceed the total limit — a misconfiguration), the tag closest to filling its reservation is still chosen, so eviction always makes progress.

### Tombstones

When a block is evicted its ID is written as a **tombstone** key (`'x' | id[32]`) with a TTL equal to the block's remaining lifetime. This ensures that:

- `Has(id)` returns `true` for tombstoned IDs — peers treating `Has` as "already seen" will not re-request the block.
- `Put` silently ignores any attempt to re-store a tombstoned block until the tombstone expires.

Once the tombstone expires naturally the ID is forgotten and the block may be re-accepted if a peer offers it again.

## BadgerDB key layout

```
block key:      'b' | id[32]                 → stamp[4] | wf[4] | created_at[8] | tag[1] | payload[4096]   (TTL set)
traversal key:  't' | created_at[8] | id[32] → wf[4] | tag[1]                                              (TTL set)
tombstone key:  'x' | id[32]                 → (empty)                                                     (TTL = remaining block TTL at eviction time)
```

The traversal key is sorted by `(created_at, id)` which supports efficient paginated listing with a keyset cursor. Tag is stored in the traversal value so eviction scans (`'b'` prefix) and listing scans (`'t'` prefix) both have access to tag without cross-key lookups.

## API

```go
Put(stamp, payload, tag) (ID, error)
Get(id) (stamp, payload, error)
Has(id) (bool, error)          // true for live blocks AND tombstones
ListIDs() ([]ID, error)
ListBlocks(pageToken, limit, powFloor, since) (nextToken, []BlockRef, error)
Prune() (int, error)
Evict(n) (int, error)
Close() error
```

- **`Put`** computes the ID and work factor, derives TTL, stores the block and traversal entry with TTL, and enforces the storage limit. Tombstoned IDs are silently skipped.
- **`Get`** / **`Has`** exclude expired blocks. `Has` additionally returns `true` for tombstones.
- **`ListIDs`** returns all live block IDs — used by transport layers building bloom filters.
- **`ListBlocks`** is a paginated traversal with `powFloor` and `since` filters. `BlockRef` includes the tag.
- **`Prune`** triggers BadgerDB value-log GC to reclaim disk space from TTL-expired entries.
- **`Evict(n)`** removes up to `n` blocks using the reservation-aware, soonest-expiring-first policy and writes tombstones. Returns the count actually evicted.

## Pagination

`ListBlocks` uses an opaque page token encoding a `(created_at, id)` cursor as 40 bytes of base64url:

```
token = base64url( uint64_bigendian(created_at) ‖ id[32] )
```

An empty input token starts from the beginning. An empty returned token means no further pages. A full page (len == limit) always produces a next token; a short page never does.

## SQLite and FlatFile backends

`SQLiteStore` and `FlatFileStore` implement the `Store` interface for testing and archival use. They accept a `Tag` parameter on `Put` but do not persist it, and `Evict` is a no-op that returns `(0, nil)`. Storage limit enforcement is not supported on these backends.

## What the blockstore does not do

- Message framing or multi-block assembly — client layer
- Sync protocol — transport layer (uses `ListIDs` to build bloom filters)
- PoW mining — caller is responsible for finding a stamp; `Put` only verifies and records the work factor
- Tag inference — the transport/networking layer decides which tag to assign

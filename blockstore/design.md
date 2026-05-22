# Blockstore Design

The blockstore is the local persistence layer for the sneakernet node. It stores, indexes, and expires opaque message blocks that are exchanged via epidemic routing.

## Block format

A block has two parts stored together but treated differently:

| Field   | Size    | Description |
|---------|---------|-------------|
| Stamp   | 4 bytes | Proof-of-work nonce |
| Payload | 2048 bytes | Opaque application data |

The **block ID** is `sha256(payload)` — the stamp is not part of the identity. Two blocks with the same payload but different stamps are the same block.

Block size is a compile-time constant (`PayloadSize = 2048`). Message framing and multi-block assembly are client-layer concerns; the blockstore is payload-agnostic.

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

This is linear for now — a block with `work_factor=0` lives 24 hours, `work_factor=4` lives 5 days, etc. The formula is intentionally easy to change in `TTLFromWorkFactor`.

Expired blocks are not returned by any read API. `Prune()` physically deletes them.

## Storage

SQLite via `modernc.org/sqlite` (pure Go, no CGo — required for mobile embedding).

### Schema

```sql
CREATE TABLE blocks (
    id          BLOB    PRIMARY KEY,   -- 32-byte sha256(payload)
    stamp       BLOB    NOT NULL,      -- 4 bytes
    payload     BLOB    NOT NULL,      -- 2048 bytes
    work_factor INTEGER NOT NULL,      -- cached at insert
    created_at  INTEGER NOT NULL,      -- unix epoch
    expires_at  INTEGER NOT NULL       -- unix epoch, computed from work_factor
);
CREATE INDEX idx_expires   ON blocks(expires_at);
CREATE INDEX idx_traversal ON blocks(work_factor, created_at, id);
```

`work_factor` is cached in the row so reads don't need to recompute argon2.

## API

```go
Put(stamp, payload) (ID, error)
Get(id) (stamp, payload, error)
Has(id) (bool, error)
ListIDs() ([]ID, error)
ListBlocks(pageToken, limit, powFloor, since) (nextToken, []BlockRef, error)
Prune() (int, error)
Close() error
```

- **`Put`** computes the ID and work factor, derives TTL, and persists atomically. `INSERT OR REPLACE` so re-inserting the same payload is idempotent.
- **`Get`** / **`Has`** exclude expired blocks at the query level.
- **`ListIDs`** returns all live block IDs — intended for transport layers building bloom filters for sync negotiation.
- **`ListBlocks`** is a paginated traversal with `powFloor` and `since` filters. Uses keyset pagination over `(created_at, id)` so cursors remain stable under concurrent writes.
- **`Prune`** is meant to be called on a schedule by the host application.

## Pagination

`ListBlocks` uses an opaque page token encoding a `(created_at, id)` cursor as 40 bytes of base64url:

```
token = base64url( uint64_bigendian(created_at) ‖ id[32] )
```

An empty input token starts from the beginning. An empty returned token means no further pages. A full page (len == limit) always produces a next token; a short page never does.

## What the blockstore does not do

- Message framing or multi-block assembly — client layer
- Sync protocol — transport layer (uses `ListIDs` to build bloom filters)
- PoW mining — caller is responsible for finding a stamp; `Put` only verifies and records the work factor

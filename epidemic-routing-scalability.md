# Epidemic Routing Scalability

> Outline / working skeleton. Sections to be expanded into prose in the same
> register as epidemic-routing-security.md. This document is the **cost ledger**:
> the security doc covers what the design buys you; this one covers what you pay.

## What "Scalability" Means Here

- **This system does not scale, and that is not the point.** In big-O terms it is
  hopeless as a global system. The honest subject of this document is not how it
  scales but what it does *instead* of scaling, and why that trade is worth it.
- **CAP: the extreme A corner.** Modeled as a distributed store, Sneakernet
  surrenders consistency completely to keep availability and partition tolerance
  absolute. No node ever holds a complete or current view; nothing tries to give
  it one. No quorum, no convergence target, no "eventually consistent" promise —
  because "eventually" assumes the partition heals.
- **Partition is the permanent baseline, not an episode.** This is delay-tolerant
  / store-carry-forward design. The unit of progress is a single *ephemeral
  contact* — a USB handoff across an air gap, a phone that syncs at home and again
  at a café. The system extracts value from contacts too brief and partial for a
  consistency-oriented system to use. (Picks up the security doc's thread:
  partition and inconsistency are the default operating state, not failure modes.)
- **The three costs, each the direct price of a property we refuse to give up:**
  - Storage is O(global volume), not O(your mail) — recipient anonymity forbids
    addressing, so "store only what's for me" is impossible by construction.
  - Bandwidth is flood-replication — reaching everyone is O(N) copies; a relay
    does O(peers) work every interval, forever.
  - Reception is trial-decryption, O(blocks × keys) — no envelope means every
    block is tried against every held key (the Bitmessage tax).
- **What it does instead of scaling:** a finite-capacity, lossy medium that
  degrades *gracefully and in a chosen order*. The store is a fixed-size cache,
  not a draining queue; the network is a fixed-throughput pipe. It never promises
  to carry all messages to all people — only to keep the most-valued recent blocks
  moving across whatever connectivity exists, shedding lowest-PoW / most-distant /
  soonest-to-expire first under pressure.
- **Full is the default state, not a warning sign.** A node or relay at capacity
  is one doing its job; empty space is wasted propagation capacity. Eviction under
  pressure is the normal working state, not a failure mode — the system never
  evicts proactively and never aims for spare room. Read "blocks get dropped" as
  the cache cycling, not as loss.
- **One mechanism, three latencies.** Internet relay, LAN, and physical transport
  are not three different systems — they are the same store-and-forward sync at
  three points on a bandwidth/latency curve. Physical transport is the extreme
  point: a *simulated relay* whose sync interval is the courier's travel time and
  whose per-contact bandwidth is the entire store. A USB drive on a circuit
  between villages is functionally a mutual relay node. This is the literal meaning
  of *sneakernet* — the courier is the network link.
- **The envelope is a capability, not a number.** Primary purpose: a fallback for
  the collapse of an open internet. Internet-mode is a happy side-benefit; even
  there the value is censorship resistance and communication safety, not
  throughput. Define the envelope by what it can still do when the network is
  partitioned, throttled, surveilled, or gone — falling back relay → LAN →
  physical as each higher-bandwidth channel is denied. No user-count commitments.

## Comparison to Tor

- Tor is the reference point most readers have; the comparison communicates the
  whole design's point in one frame.
- **Security ledger — Sneakernet dominates or equals:**
  - *Sender:* equivalent. The emission event ("this IP sent something at time T")
    is visible to a local observer in both; Tor unlinks sender from destination,
    Sneakernet has no destination to link. Neither leaks content or recipient.
  - *Recipient:* stronger — structural, no circuit to correlate; receivable
    offline or by USB.
  - *Global passive adversary:* stronger — the adversary Tor explicitly does not
    defend against; no end-to-end timing to correlate.
  - *Infrastructure coercion:* stronger — no directory authorities, no consensus,
    nothing to subpoena.
  - *Censorship / network denial:* stronger — falls back to LAN/USB; cannot be
    firewalled out of existence.
  - *Traffic fingerprint:* relay traffic is ordinary HTTPS to a web server — not
    identifiable as anonymity-tool traffic, so it does not flag the user as "using
    Tor," which is itself the targeting signal in many target regimes.
- **The price is paid entirely in scalability — never in security:**
  - *Latency:* minutes to days, non-interactive. Tor browses the live web;
    Sneakernet moves opaque blocks slowly. (Cost, not a security deficit.)
  - *Throughput / completeness:* bounded by storage and sync cadence.
  - *Forward secrecy:* Tor circuits have it; Sneakernet blocks do not — key
    compromise exposes archived ciphertext. This is a block-crypto property
    detailed in blocks.md; acknowledged here as part of an honest ledger.
- **Composability:** not strictly either/or. The push leg can ride over Tor to
  inherit its sender unlinkability; when Tor is blocked and the network is gone,
  Sneakernet still moves on LAN and USB.
- **Thesis:** strictly better security properties than Tor; the price is paid in
  scalability, latency, and forward secrecy at rest.

## Shared Propagation Model

- Epidemic store-and-forward: each node exchanges blocks with peers, who forward
  to theirs. No central coordinator; no guaranteed delivery and no delivery
  timeline.
- Convergence is probabilistic, bounded by network diameter × sync interval.
- **Redundancy is the reliability mechanism.** A block that reaches multiple
  independent relays depends on none of them to forward it; this is what stands in
  for delivery guarantees.
- **Ideal-TTL is eviction priority, not a hard expiry.** TTL = φ^(wf/2) days
  (φ ≈ 1.618; 24 h floor at wf = 0; each PoW bit ×√φ ≈ 1.272). Blocks are never
  deleted on a clock — they carry no BadgerDB TTL — they are displaced only under
  storage pressure, and ideal-TTL ranks *what goes first*. Higher-PoW blocks
  out-compete for storage longer and so propagate further. (The store is designed
  to run full; correct the old "expires naturally / store shrinks" framing.)

---

## Global-Relay Transport

### Bloom Filter Delta Sync
- Purpose: keep per-contact cost proportional to the *difference*, so even a brief
  contact does useful work — it does not escape the O, it makes the bounded
  envelope usable.
- 8,192-byte filter, 65,536 bits, 3 hashes per (id, level) pair (byte offsets
  0/8/16). Encodes identity *and* work-factor level: Add sets levels 0..wf,
  Has(id, k) tests presence at work-factor ≥ k. maxBloomPow = 16.
- Zero false-negative; false positives cause unnecessary GET fetches only.
- `since` cursor limits the delta scan to recently-added blocks.

### Peer Topology
- Static `--peers` seeds + gossip via `POST /v1/hello` and `GET /v1/peers`.
- Peer table cap: 200. Unstructured; no enforced topology or routing table.
- Private/LAN IPs are filtered from gossip responses.

### Sync Scheduling: Node vs. Relay
- Default `sync-interval`: 5 minutes (both modes).
- **Node mode** (`snk node`, rotate=true): one peer per interval, least-recently-
  pulled first; newly discovered peers (zero pullSince) sort first and get an
  immediate out-of-band sync goroutine on discovery.
- **Relay mode** (`snk relay`, rotate=false): syncs all healthy peers each
  interval — maximizes propagation at higher per-interval cost.
- Push respects the peer's advertised floor: Push raises its powFloor to the
  relay's `GetPowLimit` before uploading.

### Backoff and Failure Handling
- Each failure: skipRounds = 1 << failures, capped at 64. First successful pull
  resets failures and skipRounds to 0.
- Penalized peers are excluded from sync scheduling and from `GET /v1/peers`.

### Storage Limits and Eviction
- Per-node cap via `-storage-limit`; eviction triggered reactively inside Put when
  size exceeds the cap (never proactive — the store stays full).
- Tag reservations (physical, LAN, regional, global) are **soft**: an unused
  allocation is filled by whatever traffic is available; it only sets the point at
  which that traffic starts being displaced.
- Eviction picks the tag most over its reservation, then soonest-ideal-expiry
  first within it.
- Tombstones (TTL = 2 × ideal-TTL at eviction) block re-acceptance until peers
  still circulating the block would have dropped it; prevents evict/re-accept
  churn. Tombstones are the only keys that carry a real TTL.
- Dynamic PoW floor: median work factor of a full-store baseline, advertised as
  median − 1 (so the floor can drift down, not only ratchet up). 0 while the store
  is below half capacity.

### Geographic Distribution and Regional Tags  (relay-only)
- GeoIP classifier (GeoLite2-City MMDB) tags inbound blocks by submitter region
  (ISO 3166), enabled via `--region`. Node mode has no GeoIP and only exposes
  `-reserve-physical` / `-reserve-lan`.
- Regional reservations let a relay protect space for community-local traffic over
  distant relays.

### Known Bottlenecks
- Bloom false-positive rate grows once store size exceeds filter design capacity.
- A full scan (`since = epoch`) walks the entire store; the `since` cursor
  mitigates this in normal operation.
- Unstructured topology gives no guarantee every partition is reachable.
- **No URL normalization:** the same relay reached via http vs https, trailing
  slash, or IP vs DNS occupies separate peer-table slots (dedup is by exact map
  key, so it does not catch these). (Corrects "no gossip deduplication.")
- Relay mode syncs all peers per interval; large peer tables at high relay count
  can cause sync pile-up. Gossip also spawns an immediate sync goroutine per newly
  discovered peer, which can amplify this under a gossip burst.

---

## Local-Networking Transport

### Peer Discovery
- Subnet scan on a well-known port; no seed required. Discovered peers are added
  and synced immediately; LAN peers speak the same relay HTTP protocol.

### Sync Protocol
- Same bloom-filter delta sync and `since` cursor as global-relay. Typically a
  lower or zero PoW floor for LAN peers (operator-configured).

### Storage and Tag Reservations
- LAN-origin blocks are tagged TagLan; `-reserve-lan` protects them from being
  displaced under global relay pressure.

### Independence from Internet Connectivity
- LAN sync needs no internet. Convergence within a segment is bounded by LAN peer
  count × sync interval. A LAN island sustains its own block pool indefinitely
  while peers remain reachable.

---

## Physical Transport

### Flat-File Format and Volume Detection
- Blocks exported to a flat-file directory; any directory with a `.sneakernet`
  marker is detected and synced. Detection is polling-based (usb-interval default
  30 s).

### Sync Behavior
- Bidirectional and **full** — pulls all blocks from the volume, then pushes all
  local blocks to it. Does not use bloom delta; walks the whole store both ways.
- **Boosted-block upgrade:** a block already present is re-copied if the source
  carries a higher work factor, upgrading PoW on contact.
- All absorbed blocks are tagged TagPhysical. A separate `snk mass-storage`
  subcommand exports BadgerDB → flat-file and rebuilds the index.

### Physical Transport as a Simulated Relay
- The framing-section point, expanded: a single idle exchange is store-carry-
  forward, but a drive in *regular circulation* — a courier looping between
  villages or isolated nodes on a schedule — is functionally a mutual relay node.
  Its sync interval is the courier's loop time; its per-contact bandwidth is the
  whole store. This is ongoing convergence, just at the highest-latency / highest-
  bandwidth point on the curve.
- Moves blocks across networks with no shared connectivity. Throughput is limited
  by media write speed and file I/O, not network bandwidth or latency.

### Scalability Considerations
- Store size on the volume is bounded by media capacity; a single volume can carry
  a node's full block set. Multiple volumes can be synced in sequence at one node
  to aggregate blocks from disconnected communities.

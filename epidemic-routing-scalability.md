# Epidemic Routing Scalability

## What "Scalability" Means Here

This system, in an asymptotic global sense, does not scale. It does not aim to. Fast or unlimited growth is not the goal, and the design makes no attempt to optimize for it. Sneakernet is a hedge against a failing open internet — infrastructure that remains useful at every scale from a rural village to interplanetary messaging, precisely because it never depends on the network being fast, reliable, or present at all.

In CAP theorem terms, Sneakernet sits at the AP extreme. It surrenders consistency entirely in exchange for availability and partition tolerance. No node ever holds a complete or current view of the global block set, and nothing in the design tries to give it one. There is no quorum, no convergence target, no coordinator to elect. What most distributed systems treat as a failure condition — a partition, an unreachable peer, a message that never arrives — is here the default operating state. The network is delay-tolerant by design. A block may take minutes to propagate over an internet relay, hours over a local network island, or days carried physically across an air gap. All of these are normal. The system extracts value from contacts too brief and too partial for a consistency-oriented design to use.

## Comparison to Tor

Tor is the most widely used tool for anonymous communication, and it is a useful reference point precisely because most readers already understand it. The comparison is not a competition — Tor is a good tool that solves a real problem. The problem it solves is routing live, interactive traffic anonymously through a volunteer relay network while keeping sender and destination unlinkable. Sneakernet occupies a different position on the scalability-anonymity tradeoff: it concedes scalability almost entirely in exchange for stronger anonymity guarantees and resilience against infrastructure failure or attack.

On sender anonymity, the two systems are roughly equivalent. Both hide message content from any observer on the path. Both leak the emission event: a local observer can see that your IP connected to something at a particular time. Tor unlinks sender from destination through circuit routing; Sneakernet has no destination field to unlink from. The mechanisms differ but the practical result is similar.

Recipient anonymity is where the designs diverge structurally. Tor circuits are correlatable end-to-end by a sufficiently global passive adversary — Tor's own threat model explicitly acknowledges this. In Sneakernet there is no circuit. Every node pulls all blocks from its peers; the act of receiving reveals nothing about whether any of those blocks were addressed to that node. A recipient is indistinguishable from any other syncing node. Receiving works offline and across physical media, with no network connection required at all.

Tor depends on infrastructure: directory authorities, consensus documents, bridge distribution systems. These can be subpoenaed, blocked, or coerced. Sneakernet has none of that — no directory to take down, no consensus to subvert, no authority to pressure. Tor's traffic is also recognizable as Tor traffic, which in many regimes is itself the targeting signal — using an anonymity tool marks you as a person of interest. Sneakernet traffic looks like ordinary HTTPS to a web server, indistinguishable from any other web traffic. When the network is gone entirely, Sneakernet falls back to LAN and then to physical transport. It cannot be firewalled out of existence.

The price is paid in latency and throughput. Tor is designed for live, interactive use — browsing the web, making connections in real time. Sneakernet moves blocks over minutes to days. That is not a security deficit; it is what the design trades for everything above.

Tor supports forward secrecy. Sneakernet has no message acknowledgement at the protocol level, so forward secrecy is hard and a bit out-of-context.

The two tools are composable. The push leg of a Sneakernet sync can ride over Tor, inheriting its sender unlinkability for the submission step. Tor transport is not part of the initial release but is a near-certain addition.

## Shared Propagation Model

Sneakernet uses epidemic store-and-forward routing. Each node exchanges blocks with its peers, who forward to theirs. There is no central coordinator, no guaranteed delivery, and no delivery timeline. Redundancy is the reliability mechanism: a block that reaches multiple independent nodes depends on none of them individually to keep forwarding it. There are no delivery receipts and no acknowledgements. Replication across many nodes is what stands in for them.

The store is designed to run full. A node with unused storage capacity is a node wasting propagation capacity. Every byte of empty space is a block that could have been carried but wasn't. New blocks do not wait for space to open up; they arrive and evict something. The store is a fixed-size cache, continuously cycling, not a draining queue that empties toward zero.

Eviction is not random. Each block has an ideal-TTL derived from its proof-of-work level: a heuristic for how long a block of that quality ought to circulate. Blocks are never deleted on a timer — there is no expiry clock. They are displaced only when storage pressure demands it, with those soonest to expire or most overdue going first. A block that would have been a candidate for eviction yesterday may still be in the store today if nothing higher-priority has arrived to displace it.

### Dynamic PoW Floor

The PoW floor is not fixed. As the store fills, the minimum work factor required for a block to be accepted rises to track the median work factor of currently held blocks. A block that would have been accepted on a half-empty store may be turned away once the store is full and the population of held blocks is higher quality. The floor can also drift down — if the store empties or block quality drops, the floor follows.

This makes the system self-regulating under pressure. An attacker trying to flood the store must continuously produce blocks that out-compete half the existing population just to stay in. As their blocks raise the median, the floor rises further. The harder the store is pushed, the more expensive it becomes to push it.

For legitimate users the cost is barely noticeable. Mining one block at a time on modest hardware is fast; the floor only becomes punishing at the volumes required to sustain a flood.

---

## Global-Relay Transport

### Delta Sync

Each relay maintains a pagination token per peer recording the point at which they last synced. When two relays contact each other, the exchange is focused on what is new since that last contact — not a comparison of full stores. Per-contact cost is proportional to the volume of new blocks, not the total store size.

The PoW floor refines this further. A node can specify a minimum proof-of-work level when requesting blocks, receiving only blocks it actually intends to store. A relay with a high floor does not pull low-quality blocks and immediately discard them — it simply never requests them. What they ensure is that the work done per contact is proportional to what actually needs to move.

### Peer Topology

Relays discover each other through a combination of statically configured seed peers and gossip — each relay periodically announces itself to peers it knows and learns about others in return. The peer table is capped at 200 entries, with static seeds protected from displacement by gossip discovery. Private and LAN addresses are filtered from gossip responses, keeping the internet relay graph confined to publicly reachable nodes.

The topology is unstructured. There is no enforced routing table, no ring, no tree — just a set of peers each node has decided to talk to. In a sufficiently large random graph this approach produces a low-diameter network with favorable scaling properties. In practice, at every scale this network is expected to operate, relays will simply be all-to-all connected. The theoretical properties do not matter much; what matters is that any relay a new node can reach is effectively a gateway to the whole network. Abusive relays can be blocklisted by each node according to its own policy, without any network-wide coordination required.

### Storage Limits and Eviction

Every node operates with a fixed storage cap. Eviction is reactive — triggered when a new block arrives and the store is full — and never proactive. The store stays full; that is the point.

The internet relay layer is likely to be the highest-volume transport, and without any mitigation it would crowd out everything else. To prevent that, available storage is partitioned into soft reservations by origin tag: physical, LAN, regional, and global. A block's tag is assigned based solely on which transport delivered it first — not on any content, metadata, or where the block ultimately originated. A message that traveled physically for most of its journey but arrived at this node over the internet is tagged global. This will occasionally misfile blocks, but there is no way to know the full delivery chain, and the mislabeling is an acceptable cost of keeping the tagging system simple.

The reservations are soft. An unused physical allocation is not held empty — it fills with whatever traffic is available. The reservation only matters under pressure: when the store is full and something must go, eviction targets the tag most over its quota first, then soonest-to-expire within that tag. This ensures internet relay traffic is what gets shed when local or physical blocks need room, not the other way around.

Tombstones prevent evicted blocks from immediately re-entering the store. When a block is evicted, a record of its ID is kept for long enough that peers still circulating the block would have dropped it themselves. A peer pushing an evicted block back is turned away until that window closes.

### Geographic Distribution and Regional Tags

The tag hierarchy — physical, LAN, regional, global — has a gap between LAN and the open internet that regional tags are designed to fill. Without them, traffic from nearby nodes on the same internet segment competes directly with traffic from anywhere in the world. Regional reservations let a relay operator protect space for geographically proximate peers before global traffic displaces it.

Region is determined by the IP address of the submitting peer, looked up against an offline GeoIP database. Like all other tags, it requires no content inspection and no metadata beyond the connection itself. Regions are configured by the relay operator — a community relay might define its region as a city, a country, or whatever boundary makes sense for the people it serves.

---

## Local-Networking Transport

### Peer Discovery

Nodes on the same local network find each other automatically by scanning for the well-known Sneakernet port. No seed configuration is required. Any device speaking the protocol on the subnet is found and synced with. The network is as open as the LAN itself.

### Sync Protocol

LAN sync uses the same delta sync mechanism as internet relay transport — pagination tokens, PoW floor filtering, the same HTTP protocol. The PoW floor is typically lower or zero for LAN peers. Phones and other constrained devices that cannot mine to the same level as a desktop or relay server are full participants on a LAN; a bridging node that imposed the internet floor on LAN peers would shut out exactly the devices that make local sync valuable.

### Independence from Internet Connectivity

LAN sync requires no internet connection. A local network island — a mesh of devices that can reach each other but nothing outside — sustains its own block pool indefinitely. Blocks propagate among peers as long as at least one device remains reachable by another. This is not a degraded mode; it is the system working as intended under the conditions it was built for.

---

## Physical Transport

When a node encounters a Sneakernet volume — a USB drive, a directory on removable media — it does not simply copy files. It treats the volume as a peer relay. The volume's block store and metadata are read, and the node runs the same sync process it would run against any live internet relay: exchanging blocks in both directions, applying the same admission controls, the same eviction priority, the same tag reservations. The volume is, for the duration of the sync, a relay node that happens to be made of storage media rather than a running server.

This means a drive in regular circulation is not a one-off file transfer — it is a relay on a very slow circuit. Its sync interval is the courier's travel time; its per-contact bandwidth is the entire store. Each time it is plugged in it exchanges blocks with the node it is connected to, absorbing what is new and contributing what it carries. When it reaches the next node it does the same. Blocks propagate across networks with no shared connectivity, no internet, and no coordination beyond the physical act of handing the drive to someone.

Multiple volumes can be synced in sequence at a single node, aggregating blocks from entirely disconnected communities. The throughput limit is media write speed and file I/O — not network bandwidth, not latency, not anything the adversary controls.

---

## Operating Envelope

The system degrades gracefully under load rather than failing. As block volume increases, the PoW floor rises, low-effort messages are evicted first, and well-mined content continues to circulate. The question is not where it fails but where the hardware requirements for relay operators and the PoW requirements for senders become unreasonable.

Storage is bounded by the largest individual node, not the sum of all nodes. Adding relays increases redundancy and propagation coverage; it does not add capacity. In practice this is not a constraint. A 2 GB store holds approximately 500,000 messages — more than a busy community produces in years.

Bandwidth follows the same shape. Every relay sees all network traffic, regardless of how many relays there are. More relays means more replication overhead per node, not more capacity. Per-relay bandwidth is set by the total block generation rate of the whole network.

At roughly 150,000 active users generating around 14,000 messages per hour — one milli-discord — that is about 57 MB per hour arriving at every relay. A week of traffic fits in 9.5 GB. Both figures are comfortable on a home server or a Raspberry Pi.

The ladder is linear. Ten times that load pushes per-relay bandwidth to 14 GB per day and weekly storage to 95 GB — real server territory. At one hundred times, daily bandwidth per relay exceeds 100 GB.

Trial decryption is the binding constraint on the receiver side. A week's store at one milli-discord scale holds approximately 2.3 million blocks. Checking that store against 10 keys at 20,000 X25519 operations per second takes around 19 minutes on a desktop. The `since` cursor keeps incremental checks cheap — only new blocks since the last check need to be tried — but the full cost is paid on first sync and after long offline periods. At ten times the target scale, initial sync becomes impractical without further optimization.

PoW is the friction on the sender side. At one milli-discord scale with a low floor, mining a message takes under a second on modest hardware. As load rises and the floor follows, mining time on mobile reaches seconds to minutes.

---

## Conclusion

Sneakernet surrenders consistency, throughput, and global reach. In exchange it keeps recipient anonymity, censorship resistance, and the ability to function across any transport that can move bytes — including a person walking between two rooms with a USB drive. The costs documented here are real and are the direct price of the properties the system refuses to give up. It is not going to replace general-purpose communication tools. It is a reliable option for the people who need one when those tools are unavailable, untrustworthy, or gone.

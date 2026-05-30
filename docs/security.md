# Epidemic Routing Security

## Shared Threat Model

Sneakernet's epidemic routing operates across three transport modes — internet relay, local networking, and physical media — each with a different exposure surface. The threats described in this document apply to the routing and transport layer specifically. Block-level cryptographic properties (encryption, signing, content-addressing) are covered in [blocks.md](blocks.md); this document takes those properties as given and focuses on what an adversary can do at the network and storage level.

**Passive observer.** An adversary who can watch network traffic — at a relay's hosting provider, at an ISP, or on a local network segment — can see connection events: which IPs contacted which relay, and when. They cannot read block content or determine who sent or received a message.

**Active relay operator.** A node operator who runs a relay sees arrival timestamps, uploader IPs, and block IDs for every block that passes through their node. They cannot read content. They can selectively refuse or evict blocks by ID, and can return arbitrary data from the peer gossip endpoints. An adversarial relay operator is the strongest realistic attacker in the global-relay context.

**Sybil nodes.** An attacker can register multiple fake peer identities to manipulate the peer graph — attempting to isolate nodes, inflate apparent network size, or selectively forward traffic. The cost of a sybil node is running a reachable HTTP endpoint that speaks the relay protocol. Even if sybil peers enter the peer table, the peer cap (200 entries) bounds the fraction of the table they can occupy, and backoff penalties remove unresponsive entries over time.

**Storage exhaustion.** An attacker can attempt to flood the network with high-volume block submissions to crowd out legitimate content. The PoW admission system and per-tag storage reservations are the primary defenses.

**Selective forwarding.** A relay that receives blocks from one peer may choose not to forward them to others. Because the protocol provides no delivery receipts, omission is undetectable. The mitigation is redundancy: a block that reaches multiple independent relays does not depend on any one of them to forward it.

---

## Global-Relay Transport

### Traffic Analysis and Network Visibility

Every connection to a relay is visible to anyone who can observe the relay's network traffic — the relay's hosting provider, upstream ISPs, and any passive listener on the path. What they see is a connection from an IP address to a relay's IP address, at a specific time, carrying some volume of data. They cannot see what blocks were exchanged, who authored them, or who they were addressed to.

Recipient anonymity is strong. Every node pulls all blocks from its peers, not just blocks addressed to it — blocks are opaque at the transport layer and there is no addressing header to filter on. A node that pulls blocks cannot be distinguished from one that is simply keeping its store in sync. The act of pulling reveals nothing about whether any of those blocks were intended for that node.

Sender anonymity is weaker. A node that pushes a new block to a relay reveals that someone at that IP sent something at that time. This is the primary metadata leak in the global-relay context: the relay operator, and any observer watching the relay's traffic, can infer "a message was sent from this IP at this time," even though they cannot read it or identify its recipient.

A relay's IP address functions as a weak pseudonym for the community that uses it. The practical mitigation is to connect to a relay run by someone in your own community, or to run one yourself, rather than depending on a relay operated by a stranger or a service with incentives to cooperate with surveillance.

Sender metadata leakage can be mitigated further by having nodes regularly push dummy blocks — indistinguishable noise that establishes a baseline of constant outbound traffic regardless of whether a real message was sent. This technique works but it carries ongoing computational cost (PoW for each noise block) and bandwidth consumption. It is not encouraged by default; users with serious sender-anonymity requirements should consider it.

### Relay Operator Trust

A relay operator occupies a privileged position in the network. For every block that passes through their node they see: its SHA-256 ID, the IP address that submitted it to them directly, the block's proof-of-work level, and the time it arrived at their node. That last point matters — they see arrival time, not send time. A block may have been sent hours or days earlier and traveled through several other relays before reaching this one. The operator has no way to know.

The metadata available to a relay operator — PoW level, arrival timestamp, and one-hop origin IP — is not especially useful for surveillance. It can establish that some node submitted a block to this relay at a given time, but it cannot link that submission to a real-world identity, reveal the content, or identify the intended recipient.

A relay operator can set policies on what blocks they store and forward: minimum PoW floor, storage limits by origin tag, geographic scope. These are legitimate administrative choices — a community relay might reasonably decline to carry high-volume traffic from distant nodes in order to protect space for local blocks. These policies operate on block metadata, not content.

Targeted suppression of specific blocks is a different matter. Dropping a particular block requires knowing its ID in advance — knowledge that has to come from somewhere outside the relay itself, since block contents are encrypted and opaque. An operator acting on an externally supplied list of block IDs is a coordinated threat, but a limited one.

The deeper reason relay-level censorship is hard is that the network requires no global consensus. Partition and inconsistency are the default operating state, not failure modes. A hostile relay that withholds blocks creates a local gap in its own view of the network — which is indistinguishable from any other partition. Other nodes continue to sync, propagate, and serve blocks among themselves without reference to what any particular relay holds. There is no authoritative global block list to corrupt, no quorum to subvert, no single point whose cooperation is required for the rest of the network to function.

Some malicious behaviors — ignoring the advertised PoW floor, flooding peers with garbage — are detectable through normal sync interactions. Peers can make a local decision to stop syncing with a relay that behaves badly, without any network-wide coordination required.

### Proof-of-Work as Admission Control

Every block submitted to a relay carries a proof-of-work stamp: an Argon2id hash of the block payload mined to a target number of leading zero bits. The relay checks this stamp on every inbound block and rejects anything below its configured floor. This is the primary gate against spam and flooding.

The idea originates with Hashcash, proposed by Adam Back in 1997 as a mechanism for making email spam economically unviable: attach a proof of work to each message, and bulk senders pay a cost that individual senders barely notice. Bitmessage applied the same principle to a decentralized P2P messaging network — per-message PoW as admission control, with all nodes broadcasting all messages and trying to decrypt each one. Sneakernet follows the same lineage.

This stands in contrast to blockchain systems like Bitcoin, where mining power compounds into ongoing influence — a miner's investment earns future returns. Here, PoW buys exactly one thing: the right to store one block for its TTL. There is no compounding return, no amortization across future messages. An attacker who mines a thousand blocks has spent a thousand blocks' worth of compute. Each new block costs the same as the last.

This changes the economics of a flooding attack dramatically. Sustaining a flood requires continuously producing PoW at scale, with no payoff other than consuming storage. The floor has two layers working against this. Operators set a static minimum via [`--pow-floor`](running.md#run-a-relay-node). On top of that, the floor rises dynamically: as the store fills, it adjusts to the median work factor of currently held blocks, meaning a flooder must continuously outcompete half the existing block population just to stay in the store. A store under sustained flood pressure becomes progressively more expensive to attack.

Argon2id is memory-hard — each evaluation requires 64 MB of working memory. This makes GPU and ASIC parallelism expensive compared to CPU-based mining, which matters because flooding is a volume game. A legitimate user minting one message at a time can generate meaningful PoW on a laptop in seconds. Generating thousands of high-quality blocks fast enough to sustain a flood is a materially different problem.

The network has no global PoW floor. Each relay sets its own, and blocks below one relay's floor may be accepted at another. This is by design — low-floor relays can serve users on constrained hardware. Stricter relays won't pull low-quality blocks during [delta sync](scalability.md#delta-sync), so permissive-relay floods don't propagate far.

### Block Flooding and Storage Exhaustion

Proof-of-work raises the cost of submitting blocks but does not bound how much storage a determined attacker can consume if they are willing to pay that cost. Storage limits and eviction policy are the second line of defense.

A Sneakernet node is designed to run full. Empty storage is wasted propagation capacity — a node with spare space is a node that could be carrying more blocks for its community. The ideal state is a store at capacity, continuously cycling out lower-priority content to make room for higher-priority content as it arrives.

Every block has an ideal-TTL derived from its proof-of-work level: TTL = φ^(wf/2) days. This is not a hard expiry. Blocks are not deleted when their ideal-TTL elapses — they are evicted only when the store needs space, and ideal-TTL determines the order in which that happens. A block that would have expired yesterday may still be in the store today if nothing has arrived to displace it. Ideal-TTL is a tool for ranking eviction priority, not a deletion clock.

Tag-based reservations give operators a way to protect space for higher-priority origins — physical, LAN, regional, global — but the reservations are soft. A node with a 2 GB physical allocation that has never seen a physical block is not holding 2 GB empty; that space is filled by whatever blocks are available, most likely global relay traffic. When a physical block does arrive and the store is full, eviction targets the tag most over its reservation quota — typically global — until there is room. The physical allocation is only "used" in the sense that it sets the point at which global traffic starts getting displaced. A node that never receives physical blocks wastes nothing.

Evicted blocks are not simply deleted. A tombstone is written recording the block ID and its remaining ideal-TTL. If a peer subsequently tries to push that block back, the tombstone causes it to be rejected until the ideal-TTL would have elapsed. Without tombstones, a flooder could continuously re-push evicted blocks, forcing the store into a permanent churn of evict-and-re-accept.

The dynamic PoW floor ties these mechanisms together. As the store fills, the floor rises to the median work factor of current contents. A flooder trying to maintain presence must produce progressively higher-quality blocks as the store fills — and those blocks raise the median further. The system pushes back harder the harder it is pushed.

### Sybil Resistance in Peer Gossip

Peer lists in Sneakernet are ungoverned: any node can announce itself via `POST /v1/hello` and appear in `GET /v1/peers` responses. There is no authentication, no vetting, and no global registry. This openness is intentional — it keeps the barrier to running a relay low — but it means the peer graph can be poisoned by sybil nodes.

The most serious sybil-based attack is an eclipse attack: flooding a target node's peer table with attacker-controlled entries until the node syncs exclusively with hostile relays. An eclipsed node still receives blocks — the attacker's relays can serve them — but the attacker controls which blocks the node sees and can selectively withhold content without the node having any honest peers to cross-check against.

Eclipse attacks become harder as the honest network grows. An attacker must operate enough reachable, syncing HTTP endpoints to crowd out legitimate peers within the 200-entry peer table cap. Static seed peers (`--peers`) are never evicted by gossip discovery, which anchors at least some honest connections regardless of what gossip returns. A node with no static seeds and an aggressive gossip attacker is genuinely vulnerable; configuring at least one trusted static peer is the primary practical defense.

The deeper resilience is architectural: the internet relay layer is not the only transport. LAN discovery and physical sync operate independently of the peer table entirely. A node that is fully eclipsed at the relay level can still exchange blocks with neighbors on the same local network, and can receive blocks carried physically on a USB drive. Mobile phones are a particularly important case — a phone syncing over WiFi at home, traveling across a city, and syncing again at a café or a meeting is a mobile relay node that moves blocks between communities with no internet relay involvement at all. An attacker who controls the entire internet relay layer still cannot prevent blocks from propagating through these channels.

### Gossip Peer List Manipulation

The peer gossip system is intentionally open: any relay can return any URLs from `GET /v1/peers`, and there is no signature or authority to verify the list is honest. A malicious relay can exploit this to attempt a partition attack — returning only attacker-controlled peer URLs in hopes of gradually filling a node's peer table with sybil entries and cutting it off from the honest network.

The primary defense is the static seed list. Peers configured via `--peers` are permanent fixtures in the peer table and are never displaced by gossip discovery. A node with at least one honest static seed retains a guaranteed path to the honest network regardless of what gossip returns. This makes the static seed list the most important configuration decision for a node's long-term connectivity.

Private and LAN IP addresses are filtered before being included in any gossip response. A malicious relay cannot use the gossip mechanism to redirect internet-connected nodes to internal addresses.

Peers that misbehave in observable ways are penalized locally and removed from gossip propagation. The key behavioral contract in [delta sync](scalability.md#delta-sync) is that when a node sends a request with a `pow_floor` field, the responding relay must respect it — returning only block IDs at or above that floor. A node's store will always contain many blocks below its current dynamic floor (the floor is the median, so half the store sits below it by definition), but those are never included in a response to a request that specifies a higher floor. A relay that ignores the requested floor wastes bandwidth and can be identified doing so. Similarly, a relay that triggers rate-limit protections or behaves inconsistently during sync is penalized by the nodes that observe it. Penalized peers are excluded from that node's own `GET /v1/peers` responses — they stop being advertised to the rest of the network. No global coordination is required: each node makes its own judgment, and a consistently bad actor finds its reach in the gossip graph quietly shrinking as more nodes apply their own penalties independently.

As with eclipse attacks, the resilience of the broader network grows with its transport diversity. A gossip-manipulation attack that successfully partitions one node from the internet relay layer does not affect that node's ability to sync over LAN or receive blocks physically.

---

## Local-Networking Transport

### Network Visibility on a Local Segment

LAN sync operates on the same fundamental model as internet relay transport: blocks are given to anyone who asks. A device on the same local network that runs a Sneakernet node becomes a peer and receives blocks through normal epidemic sync. This is not a special risk — it is the system working as intended. The same analysis from the global-relay section applies: peers receive opaque ciphertext they cannot read without keys, and the only meaningful metadata exposure is the sender timing leak inherent to pushing any new block.

The one property distinct to LAN is that peer discovery is automatic. There is no static seed list to configure; any device speaking the protocol on the subnet is found and synced with. The network is as open as the LAN itself.

### PoW Floor in LAN Context

The PoW floor is contextual to the transport medium. A node serving both LAN and internet peers applies different floors to each: internet-origin submissions are held to the dynamic median floor — rising as the store fills — while LAN-origin blocks may be accepted at a lower threshold. This matters in practice because phones and other constrained devices on a LAN may not be able to mine to the same level as a desktop or server. A bridging node that imposes the internet floor on LAN peers would shut out exactly the mobile nodes that make LAN sync valuable. [Soft reservations](scalability.md#storage-limits-and-eviction) protect LAN-origin blocks from being displaced by higher-volume internet traffic regardless of their lower PoW level.

---

## Physical Transport

### Auto-Sync on Volume Mount

Physical sync is triggered automatically: any directory with a `.sneakernet` marker that appears under the configured watch path is synced on the next check interval. There is no confirmation prompt, no inspection of the volume's contents before sync begins, and no distinction between a trusted volume and an unknown one. Plugging in a drive and waiting is sufficient to exchange blocks in both directions.

This is intentional. Friction in the sync process defeats the purpose of physical transport — the value is that anyone can carry a drive, hand it to someone, and blocks move. Requiring user intervention would break that model for automated or unattended nodes.

Automatic parsing of untrusted media warrants attention to the risk of autorun-style exploits: a crafted volume could attempt to trigger vulnerabilities in the parsing code. In practice the risk is minimal. The sync process reads a tightly specified flat-file format and validates every block against its SHA-256 content address before accepting it. There is no execution, no dynamic loading, and no interpretation of block contents — only fixed-width binary parsing against a known schema.

### Blocks from Physical Media

Physical transport exists to carry blocks across boundaries that network connectivity cannot reach. A USB volume arriving from another community may carry the most important blocks in the store — messages that could not travel any other way. Syncing from a physical volume is a first-class operation.

The same admission controls apply as with any other source: PoW floor, content-address verification, and [tombstone checks](#block-flooding-and-storage-exhaustion). These are not defenses against physical transport specifically — they apply uniformly to every block regardless of origin. A block below the floor is rejected; a block whose SHA-256 ID does not match its content is rejected; a block whose ID appears in the tombstone list is rejected until its ideal-TTL elapses.

### Network Visibility of Physical Transfer

The act of physical sync itself generates no network traffic — a passive observer watching internet or LAN connections sees nothing during the exchange. However, the blocks transferred physically do not stay quiet. Once a node absorbs a USB volume, it begins propagating those blocks to its network peers through normal epidemic sync. A burst of novel high-PoW blocks appearing on a node that previously lacked them is an observable signal: it suggests that a physical transfer occurred, likely bridging two previously partitioned networks.

This is the desired behavior — those blocks should propagate — but it is worth understanding that physical transfer leaves a downstream network signature even though the transfer itself is invisible. An observer watching a relay connected to the receiving node can infer that a physical handoff happened without knowing what was transferred, when, or between whom.


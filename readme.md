SNEAKERNET
==========

> Never underestimate the bandwidth of a station wagon full of tapes hurtling down the highway.
> — Andrew S. Tanenbaum

Sneakernet is a delay-tolerant encrypted messaging infrastructure built for the gaps in normal communication — network outages, surveillance, physical isolation, infrastructure failure. It moves fixed-size encrypted blocks across multiple transport modes: internet relay nodes, LAN sync, and physical media. Any combination of those paths can carry a message from sender to recipient with no central coordinator and no single point of failure.

The protocol has no metadata. Blocks carry no sender field, no addressing header, no routing information. The network cannot distinguish a message from random noise. Applications like the bundled chat client add identity and conversation as a client-side layer on top of that substrate.

This project exists because people should be able to talk to each other. It is community-run by design — there is nowhere to put a meter, no account infrastructure to monetize, no central node to subpoena or shut down.

## How it works

The system has three layers.

**Blocks.** Everything stored and exchanged is a fixed 4096-byte unit of opaque data, content-addressed by SHA-256. Each block carries a proof-of-work stamp that determines how long it lives in storage. Blocks are completely opaque at the storage layer — the network cannot distinguish a message from random noise.

**Transport.** Blocks spread by epidemic routing: each node passes blocks to peers, who pass them to theirs. Currently three transport modes run together: internet relay nodes that gossip peer lists and sync via delta exchange; LAN sync that finds peers automatically on the local network without any internet connection; and physical sync over USB drives that any node will absorb automatically on mount. A drive in circulation is a relay on a slow circuit.

**Messages.** At the application layer, blocks carry encrypted messages using modern encryption. Every block looks like random bytes without the right key. There is no addressing header, no sender field — the only way to know whether a block is for you is to try to decrypt it. Signing is optional; messages can be sent anonymously. Groups use shared passphrases.

### What this doesn't protect

See [docs/security.md](docs/security.md) for the full threat model. Two things worth knowing up front:

- **There is no recovery.** Keys, messages, and identity are self-custodied. If your key is lost or compromised there is no support, no reset, and no way to revoke it.
- **Relay access is visible.** An observer watching a relay's IP traffic can see which IPs connect to it. Using a relay your community operates reduces this risk.

The browser client has additional limitations — see [docs/web-client.md](docs/web-client.md).

## Getting started

```
git clone https://github.com/brendanbenshoof/sneakernet
cd sneakernet
go build ./cmd/snk
./snk node -peers https://relay.example.com
```

Open `http://127.0.0.1:8080` in a browser to use the local interface.

See **[docs/running.md](docs/running.md)** for all options: running a relay, syncing to a USB volume, storage limits, LAN peering, and more.

## Documentation

| Document | What it covers |
|---|---|
| [docs/blocks.md](docs/blocks.md) | Block format, cryptographic primitives, encryption schemes, distinguishability, forward secrecy, quantum resistance |
| [docs/messaging.md](docs/messaging.md) | Plaintext message format, identities, signing, threading, fragmentation, identity PoW stamps |
| [docs/security.md](docs/security.md) | Threat model, traffic analysis, relay operator trust, PoW admission control, sybil resistance, physical transport risks |
| [docs/scalability.md](docs/scalability.md) | Operating envelope, Tor comparison, propagation model, storage and bandwidth scaling, trial decryption costs |
| [docs/running.md](docs/running.md) | Build, node and relay configuration, USB sync, all CLI flags |
| [docs/web-client.md](docs/web-client.md) | Browser UI capabilities and limitations vs. native node |
| [docs/ethics.md](docs/ethics.md) | Ethical status of the project: goods, harms, tradeoffs, relay operator responsibilities |

## What is in this repository

```
blockstore/     Content-addressed block storage (BadgerDB, SQLite, flat-file backends)
transport/
  relay/        HTTP relay node: block exchange, bloom filters, gossip peering, GeoIP tagging
  lan/          LAN peer discovery by subnet scan
client/         Message encryption/decryption, keystore, inbox, message format
client/api/     HTTP API for local node access (used by web UI and mobile clients)
ui/             Web interface (browser-side and server-side rendering modes)
cmd/snk/        CLI: `snk node` (personal), `snk relay` (public relay), `snk mass-storage` (USB sync)
docs/           Design documentation
```

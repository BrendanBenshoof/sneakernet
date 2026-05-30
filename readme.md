SNEAKERNET
==========

> Never underestimate the bandwidth of a station wagon full of tapes hurtling down the highway.
> - Andrew S. Tanenbaum

# What is this?

Sneakernet is a tool for people who need to communicate safely when they cannot trust the network — or when there is no network at all.

The name comes from the old practice of carrying data physically: by foot, by hand, on a USB drive. That is still a transport mode here. But the system extends that idea to cover every way people actually pass information to each other: local wireless networks, internet relays run by community members, and literal physical media exchanged in person.

## Why it matters

The right to communicate privately is not a product feature. It is something people need to support each other, organize, stay safe, and maintain dignity. That right is routinely attacked — by states, by platforms, by network operators who surveil or throttle traffic.

This project is a tool for people to help each other maintain that right, without depending on any company, server, or infrastructure they do not control. Anyone can run a relay node and contribute storage and bandwidth to the network. Anyone can carry a USB drive and be a link in the chain. The system is designed to keep working even when parts of it fail or are attacked.

There is no central point to shut down, no account to deactivate.

## How it works

The system has three layers.

**Blocks.** Everything stored and exchanged is a fixed 4096-byte unit of opaque data, content-addressed by SHA-256. Each block carries a proof-of-work stamp that determines how long it lives in storage. Blocks are completely opaque at the storage layer — the network cannot distinguish a message from random noise.

**Transport.** Blocks spread by epidemic routing: each node passes blocks to peers, who pass them to theirs. Three transport modes run together: internet relay nodes that gossip peer lists and sync via delta exchange; LAN sync that finds peers automatically on the local network without any internet connection; and physical sync over USB drives that any node will absorb automatically on mount. A drive in circulation is a relay on a slow circuit.

**Messages.** At the application layer, blocks carry encrypted messages. Every block looks like random bytes without the right key. There is no addressing header, no sender field — the only way to know whether a block is for you is to try to decrypt it. Senders use ephemeral X25519 key agreement and XChaCha20-Poly1305 encryption. Signing is optional; messages can be sent anonymously. Groups use shared passphrases.

### What this doesn't protect

- **Endpoint security** — if the device running the node is compromised, the system cannot help.
- **Relay access visibility** — an observer watching a relay's IP traffic can see which IPs connect to it. Using a relay your community operates reduces this risk.
- **Browser client limitations** — no proof-of-work mining (messages get the minimum 24-hour TTL), inbox is memory-only. See [docs/web-client.md](docs/web-client.md).

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

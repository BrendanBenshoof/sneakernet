
SNEAKERNET
==========

> Never underestimate the bandwidth of a station wagon full of tapes hurtling down the highway.
> - Andrew S. Tanenbaum

*This repository is not yet ready for public release. Please do not share it beyond yourself for now — that moment is coming soon.*

# What is this?

Sneakernet is a tool for people who need to communicate safely when they cannot trust the network — or when there is no network at all.

The name comes from the old practice of carrying data physically: by foot, by hand, on a USB drive. That is still a transport mode here. But the system extends that idea to cover every way people actually pass information to each other: local wireless networks, internet relays run by community members, and literal physical media exchanged in person.

## The problem it solves

Most communication tools either require trusting a central server or trust the network to keep your metadata private. Both assumptions fail under exactly the conditions when safe communication matters most — surveillance, censorship, infrastructure shutdowns, or adversarial network operators.

Sneakernet is built for those conditions. It works with intermittent connectivity. It does not require any central authority. And it is designed so that an adversary who intercepts traffic cannot determine who is talking to whom, or even that any particular block of data is a message rather than noise.

## How it works

The system has three layers.

### Blocks

Everything stored and exchanged is a **block**: a fixed 4096-byte unit of opaque data. Blocks are content-addressed (identified by their SHA-256 hash) and carry a proof-of-work stamp that determines how long they live in storage. Higher-work blocks survive longer; low-effort blocks expire quickly. This prevents the network from being flooded without requiring accounts or gatekeepers.

Blocks are completely opaque at the storage layer. The blockstore does not know whether a block is a message, a file fragment, or anything else.

### Transport

Blocks spread through the network by epidemic routing: each node passes blocks to peers, who pass them to their peers. There are three transport modes that can run together:

- **Relay nodes** — internet-accessible HTTP servers that store blocks and sync with other relay nodes via bloom filter exchange. Any community member can run one. Relay nodes gossip peer lists to each other so the network self-discovers. Storage limits and per-origin reservations let operators protect space for locally-produced blocks against being crowded out by distant traffic.

- **LAN sync** — nodes on the same local network find each other by scanning for the well-known sneakernet port. This works without any internet connection.

- **Physical sync** — blocks can be exported to a flat-file directory on a USB drive. A node watching a USB mount point will automatically sync with any sneakernet volume it finds there. This is the literal sneakernet: carry blocks on a drive, hand it to someone, they plug it in and their node absorbs the data.

### Messages

At the application layer, blocks carry encrypted messages. The encryption scheme is designed so that:

- Every block looks like random bytes to anyone who does not hold the right private key.
- There is no addressing header, no sender field, no metadata that links a block to any identity.
- The only way to know whether a block is a message for you is to try to decrypt it.

Each message is encrypted with a fresh ephemeral X25519 key pair. ECDH with the recipient's public key produces a shared secret; the plaintext is padded to a fixed size (so ciphertext length reveals nothing) and encrypted with XChaCha20-Poly1305.

Senders can optionally sign messages with an Ed25519 identity key, which lets recipients verify authorship. Signing is optional — messages can be sent anonymously. Groups communicate via shared symmetric keys (channels).

Messages can span multiple blocks via fragmentation, and replies carry a skip-list of thread references so conversations can be reconstructed without requiring access to the full history — important when messages arrive out of order or some blocks have already expired.

## Getting started

See **[RUNNING.md](RUNNING.md)** for build instructions and how to run a personal node, a relay, or sync to a USB volume.

Every relay node also serves a browser UI at `/app` — no installation required, works from any device with a browser. Read **[web_client.md](web_client.md)** for what it can and cannot do.

## Why it matters

The right to communicate privately is not a product feature. It is something people need to support each other, organize, stay safe, and maintain dignity. That right is routinely attacked — by states, by platforms, by network operators who surveil or throttle traffic.

This project is a tool for people to help each other maintain that right, without depending on any company, server, or infrastructure they do not control. Anyone can run a relay node and contribute storage and bandwidth to the network. Anyone can carry a USB drive and be a link in the chain. The system is designed to keep working even when parts of it fail or are attacked.

There is no central point to shut down, no account to deactivate, no metadata to subpoena.

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
```

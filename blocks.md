# Block Formats

This document describes the format and immediate cryptographic properties of a Sneakernet block. It covers how blocks are structured, how the two encryption schemes work, and what an adversary can and cannot determine from ciphertext alone. It does not cover proof-of-work, block lifetime, transport, or the plaintext message format inside the encrypted payload — those are addressed in separate documents.

Sneakernet stores and exchanges two kinds of encrypted blocks: **public-key blocks**, encrypted for a specific recipient, and **channel blocks**, encrypted with a shared symmetric key. Both are exactly 4096 bytes and are content-addressed by `SHA-256(payload)`.

---

## Cryptographic Primitives

| Primitive | Role | Key property |
|---|---|---|
| X25519 | Ephemeral key agreement | Any 32-byte value is a valid public key — no point validation step, no invalid-curve attacks |
| Ed25519 | Identity signing | Optional — messages can be sent anonymously without a signing key |
| XChaCha20-Poly1305 | AEAD encryption | 192-bit random nonce; constant-time on all hardware |
| SHA-256 | Key derivation, block ID | Uniform output regardless of DH shared-secret distribution |

**X25519 and Ed25519 share the same underlying curve (Curve25519).** A single identity key pair serves both signing and encryption. The Ed25519 public key is converted to an X25519 public key via the birational map between the Edwards and Montgomery curve forms; the private scalar is derived from the same seed via SHA-512 with standard clamping. One key pair, two uses.


**XChaCha20-Poly1305 is chosen over AES-GCM for its nonce properties.** AES-GCM uses a 96-bit nonce; with random nonce generation, collision probability becomes non-negligible above ~2³² blocks per key. XChaCha20-Poly1305 uses a 192-bit nonce, making random generation safe across the full expected lifetime of any key. It is also constant-time on hardware without AES acceleration, which matters for mobile and embedded nodes.

**Nonces are generated randomly** rather than maintained as counters. In a delay-tolerant network there is no reliable sequencing between a sender and any given block — a counter would require state that cannot be safely maintained across disconnected sessions. Random 192-bit nonces are statistically safe.

---

## Payload Layout

Both block types share the same 4096-byte layout:

```
[0:32]    key material (32 bytes)
[32:56]   XChaCha20-Poly1305 nonce (24 bytes)
[56:4096] ciphertext  (4024 bytes plaintext + 16 bytes auth tag)
```

The two types differ only in what occupies `[0:32]` and how the symmetric key is derived from it. Nonce position, cipher, and ciphertext length are identical.

---

## Public-Key Block

A public-key block is encrypted for a single recipient identified by their Ed25519 public key.

### Identity conversion

Sneakernet identities are Ed25519 key pairs. The same key material is reused for X25519 Diffie-Hellman via the birational map between the Edwards and Montgomery forms of Curve25519.

Public key:
```
x25519_pub = EdwardsPoint(ed25519_pub).BytesMontgomery()
```

Private key (derived from the Ed25519 seed):
```
h           = SHA-512(ed25519_seed)
scalar      = h[0:32]
scalar[0]  &= 248    // clear cofactor bits
scalar[31] &= 127    // clear high bit
scalar[31] |= 64     // set second-highest bit
x25519_priv = scalar
```

### Encryption

```
ephemeral_priv, ephemeral_pub = X25519.GenerateKey()
shared    = ECDH(ephemeral_priv, recipient_x25519_pub)
key       = SHA-256(shared)
nonce     = random 24 bytes
ct        = XChaCha20-Poly1305(key, nonce).Seal(plaintext)

payload[0:32]    = ephemeral_pub
payload[32:56]   = nonce
payload[56:4096] = ct
```

### Decryption

```
ephemeral_pub = payload[0:32]
shared        = ECDH(recipient_x25519_priv, ephemeral_pub)
key           = SHA-256(shared)
nonce         = payload[32:56]
plaintext     = XChaCha20-Poly1305(key, nonce).Open(payload[56:4096])
```

Decryption fails with an authentication error if the block was not encrypted for this recipient. There is no recipient address field.

---

## Channel Block

A channel block is encrypted with a 32-byte shared key known to all channel members. A per-block random salt ensures a distinct encryption key per block even when the channel key is reused across many blocks.

### Encryption

```
salt      = random 32 bytes
block_key = SHA-256(channel_key ‖ salt)
nonce     = random 24 bytes
ct        = XChaCha20-Poly1305(block_key, nonce).Seal(plaintext)

payload[0:32]    = salt
payload[32:56]   = nonce
payload[56:4096] = ct
```

### Decryption

```
salt      = payload[0:32]
block_key = SHA-256(channel_key ‖ salt)
nonce     = payload[32:56]
plaintext = XChaCha20-Poly1305(block_key, nonce).Open(payload[56:4096])
```

Decryption fails if the channel key is wrong.

### Channel key derivation

The 32-byte channel key may be derived from a human-memorable passphrase. The primary use case is a simple deterministic derivation with no salt:

```
channel_key = SHA-256(passphrase)
```

A channel is a public forum: any node that knows the passphrase is a member, and membership is established solely by sharing the passphrase out of band. All members must independently derive the same key without any additional coordination. This derivation preserves the one-step join property — knowing the passphrase is sufficient.

Any message encrypted with a human-memorable passphrase should be treated as public in the long term. Blocks replicate widely and are retained by nodes that cannot distinguish channel traffic from any other block. An adversary collecting blocks today can attempt to break the passphrase at any future point when compute is cheaper or the passphrase is leaked. The confidentiality of a channel block is only as strong as the passphrase entropy — and human-chosen phrases routinely fall short of that bar.

Stronger key derivation — for example, Argon2id with a community context salt — is entirely viable and would meaningfully raise the cost of offline attacks, but is not part of this specification.

---

## Distinguishability

Without this mitigation, the two block types would be partially distinguishable.

**Public-key blocks** place an X25519 public key at `[0:32]`. An X25519 public key is a u-coordinate on Curve25519, encoded as a 32-byte little-endian integer. The field modulus is p = 2²⁵⁵ − 19, so all valid u-coordinates are strictly less than 2²⁵⁵. In the little-endian encoding this means **bit 255 — the most significant bit of byte 31 — is always 0** for a naively encoded ephemeral key.

**Channel blocks** place a uniformly random 32-byte salt at `[0:32]`. That bit is 0 or 1 with equal probability.

Without any countermeasure, this would be a one-way distinguisher: `payload[31] & 0x80 != 0` unambiguously identifies a channel block. Roughly half of all channel blocks would be immediately identifiable by a passive observer.

### Mitigation: randomised bit 255

RFC 7748 specifies that X25519 implementations must mask the high bit of the u-coordinate before performing the scalar multiplication, regardless of its value. The shared secret is therefore identical whether bit 255 is 0 or 1. Sneakernet exploits this to close the distinguisher.

After placing the ephemeral public key into the payload, bit 255 is replaced with a uniformly random bit:

```
payload[31] = (payload[31] & 0x7f) | (random_byte & 0x80)
```

This makes the distribution of bit 255 uniform in public-key blocks, matching channel blocks. A passive observer with no key cannot determine block type from this field.

### No-key information summary

| Observable | Public-key block | Channel block |
|---|---|---|
| `payload[31] & 0x80` | uniform random (½ / ½) | uniform random (½ / ½) |
| `payload[32:56]` (nonce) | uniform random | uniform random |
| `payload[56:4096]` (ciphertext) | pseudorandom | pseudorandom |
| Recipient identity | not present | not present |
| Sender identity | not present | not present |
| Plaintext length | fixed (4096 bytes) | fixed (4096 bytes) |

---

## Forward Secrecy

The absence of recipient forward secrecy is the most significant cryptographic limitation of this design.

If an adversary ever obtains a recipient's private key, they can decrypt every block ever addressed to that key — including blocks collected and archived years before the key was compromised. Because blocks replicate widely and nodes retain them for days to weeks, bulk collection by a patient adversary is realistic. This is not a theoretical weakness: it is the expected outcome of key compromise.

The sender side fares better. The block encryption key is derived from an ephemeral X25519 key pair that is discarded immediately after use. Compromise of the sender's signing key does not expose block encryption keys. That asymmetry is cold comfort for recipients.

### Why this cannot be fixed without breaking the network model

The Double Ratchet — the mechanism behind forward secrecy in Signal and similar protocols — advances its state when the recipient sends a reply carrying a new ephemeral key. The sender picks up that key and the old one is discarded. Forward secrecy follows from the fact that each reply ratchets both parties forward.

That mechanism has a hard prerequisite: the recipient must eventually reply. In Sneakernet, the recipient is never obligated to respond or acknowledge receiving a message. They may read a block and stay silent indefinitely. They may be offline for weeks. There is no reply, so there is no ratchet advance, so there is no forward secrecy. This is not a solvable engineering problem — it is a consequence of the network's fundamental design guarantee that one-way communication works.

### Why rotation cannot even approximate forward secrecy here

Without a ratchet, the only alternative is out-of-band key rotation: the recipient publishes a new public key, old private keys are deleted, and senders switch to the new one. This fails for the same reason. The sender cannot know whether a block they are writing now will be received before or after the recipient's next key rotation. Propagation delay is unbounded and unknown. A sender encrypting to the new key may produce a block the recipient cannot decrypt because the old key was still the right one; a sender encrypting to the old key defeats the purpose.

The cost compounds further because Sneakernet recipients have no addressing header to filter on — every block must be tried against every key held. A recipient maintaining `k` active key epochs pays `k×` the decryption cost. There is no rotation frequency at which the forward secrecy window is short enough to matter and the decryption cost is acceptable.

### What this means in practice

Protecting past messages depends entirely on protecting the private key. Losing the key means losing all past messages — not just future ones. For high-risk users, the correct response is to treat key compromise as a total loss: assume all past ciphertext is readable, rotate to a new identity, and consider prior communications exposed.

---

## Quantum Resistance

The symmetric primitives — XChaCha20-Poly1305 and SHA-256 — are quantum-resistant at current key sizes. Grover's algorithm provides a quadratic speedup against symmetric ciphers and hash functions, halving the effective security level. A 256-bit key retains 128-bit post-quantum security, which is considered acceptable.

The asymmetric primitives — X25519 and Ed25519 — are not quantum-resistant. Both are based on the elliptic curve discrete logarithm problem, which Shor's algorithm solves in polynomial time on a sufficiently powerful quantum computer. A quantum adversary with a capable machine could recover any private key from the corresponding public key, decrypt all past ciphertext, and forge signatures.

Post-quantum replacements exist. NIST has standardized ML-KEM (key encapsulation, replacing X25519) and ML-DSA (signatures, replacing Ed25519). However, migrating to them is not a drop-in change — it would require a radical redesign of the block schema:

- An ML-KEM-768 public key is **1,184 bytes**, versus 32 bytes for X25519. The outer block's key material field would grow by 1,152 bytes, reducing available plaintext from 4,024 bytes to 2,872 bytes — a 29% reduction — before any content is written.
- An ML-DSA-65 signature is **3,309 bytes**, versus 64 bytes for Ed25519. The current plaintext header allocates 64 bytes for the signature field. Accommodating ML-DSA would consume the entire plaintext of the current block format with nothing left for content.

Fitting post-quantum primitives into the current 4096-byte block size is not possible without removing other header fields. A viable migration would require increasing the block size substantially — which cascades into the proof-of-work parameters, TTL calculations, storage reservations, transport framing, and every node's on-disk format. It is a hard fork of the entire protocol, not an upgrade.

Bluntly put, while I won't resist migration to Quantum Resistant encryption where it is cheap to do so, I don't see it as worthwhile endevor for this (or any other) project where it incurs meaningful expense.

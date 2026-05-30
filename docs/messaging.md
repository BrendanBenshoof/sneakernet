# Messaging System

This document describes the messaging protocol built on top of Sneakernet's 
encrypted block layer. It covers the plaintext format that lives inside a 
decrypted block, how senders identify themselves, how identity proof-of-work 
stamps function as a spam-prevention mechanism, and how threads and large 
messages are handled. It does not cover [how blocks are encrypted](blocks.md), [stored](security.md#block-flooding-and-storage-exhaustion), or 
[transported](scalability.md) — those are addressed in separate documents.

---

## Overview

A Sneakernet message is the plaintext that lives inside a decrypted block. The 
encrypted block layer guarantees confidentiality and deniability of delivery; 
the messaging layer on top of that provides structure for conversations: sender 
identity, threading, fragmentation, and timestamp.

Every plaintext is exactly 4024 bytes — the fixed plaintext capacity of a 
4096-byte block after encryption overhead. Messages that fit are single-block. 
Messages that do not fit are split into a fragment sequence.

---

## Plaintext Layout (v2)

```
[0:4]     magic "SNK\x02"
[4]       msg_type
[5]       flags  (bit 0 = IsFragment)
[6:14]    timestamp  int64 LE (Unix seconds; 0 = unknown)
[14:46]   sender_pub (32-byte Ed25519 public key; all-zeros = anonymous)
[46:110]  signature  (64-byte Ed25519 signature; all-zeros = unsigned)
[110:366] thread_refs[8]  (8 × 32-byte skip-list; all-zeros entry = absent)
[366:398] frag_id    (32 bytes; all-zeros = not fragmented)
[398:400] frag_index  uint16 LE
[400:402] frag_total  uint16 LE  (1 = single block)
[402:404] content_len uint16 LE
[404:]    content + zero padding
```

The magic bytes `SNK\x02` identify this as a v2 plaintext and distinguish it 
from legacy v1 format. A receiver that encounters an unknown magic value 
discards the block.

The total header is 404 bytes, leaving 3620 bytes for content. The content_len 
field records the actual content length; the remainder of the plaintext is zero 
padding. The `msg_type` field is 0 for all current messages (UTF-8 text).

---

## Identities

An identity is an Ed25519 key pair. The public key is the stable, unique 
address for a participant. It serves two purposes: it is the encryption address 
(via the Edwards-to-Montgomery birational map, described in [blocks.md § Identity conversion](blocks.md#identity-conversion)), and it is the signature verification key for signed messages.

A single 32-byte public key is all a contact needs to share. There is no 
separate encryption key. Contacts are stored by public key and given a local 
human-readable name; the name is a local label only and is never transmitted.

### Sending

A sender can send either anonymously or signed:

- **Anonymous**: `sender_pub` is all-zeros, `signature` is all-zeros. The 
recipient cannot verify the source.
- **Signed**: `sender_pub` contains the sender's Ed25519 public key. The 
signature field is computed over the entire plaintext buffer with the signature 
bytes zeroed first — this makes the signature deterministic and 
self-verifying.

Signing proves that the message was written by whoever holds the private key 
for `sender_pub`. It does not prove the sender's real-world identity, and it 
does not prevent a block from being replicated or stored by anyone. Signed and 
anonymous messages are indistinguishable to an outside observer — both are 
encrypted inside the same opaque block format (see [blocks.md § Distinguishability](blocks.md#distinguishability)).

### Signature verification

On decryption, a receiver that finds a non-zero `sender_pub` verifies the 
signature immediately. Any message claiming a sender whose signature does not 
verify is discarded silently. This prevents a malicious block from falsely 
attributing content to someone else's public key.

Anonymous messages (all-zero `sender_pub`) are accepted without any signature 
check.

---

## Identity Strings

An identity string is how a signed sender announces their public key and 
display name to a new contact in a human-readable way. The format is:

```
snk:<name>/<pubkey_b64url> <stamp_b64url>
```

Where:
- `snk:` is a fixed prefix identifying this as a Sneakernet identity string
- `<name>` is the sender's chosen display name (1–64 characters, no `/`, no 
control characters)
- `<pubkey_b64url>` is the sender's Ed25519 public key, base64url-encoded 
without padding
- `<stamp_b64url>` is the sender's identity PoW stamp, base64url-encoded 
without padding

The identity string appears as the first line of message content when the 
sender wants to be contactable. A recipient who sees a valid identity string 
can extract the public key and add the sender to their contact list under the 
given name.

The name in the string is not authoritative — the recipient can choose any 
local name. The public key is what identifies the sender. Two identity strings 
with the same name but different public keys are different people.

### Parsing

A receiver parses an identity string by:
1. Confirming the first line has the `snk:` prefix and the expected structure
2. Extracting and verifying that the embedded public key matches the 
`sender_pub` field in the plaintext header
3. Extracting the stamp and computing its work factor

If the embedded public key does not match `sender_pub`, the identity string is 
invalid and should be ignored. The match requirement means a sender cannot 
forge an introduction for someone else's public key.

---

## Identity Proof-of-Work Stamps

### Purpose

In an open network, any node can generate a key pair and send messages. Without 
any cost to creating an identity, a spammer can generate unlimited disposable 
identities and flood the network with unwanted content. Identity PoW stamps 
impose a computational cost on establishing an identity, making mass identity 
creation expensive.

The stamp is tied to a specific public key. It cannot be reused for a different 
key, transferred between identities, or pooled. A sender who wants to be taken 
seriously invests compute once per identity, not once per message.

### Construction

An identity PoW stamp is a 16-byte random nonce mined to minimize the output of:

```
argon2id(stamp ‖ pubkey, salt="sneakernet-idpow-v1",
         time=1, memory=64MB, threads=1, key_len=32)
```

The work factor is the number of leading zero bits in the argon2id output. 
Higher is better. A stamp with work factor 0 is trivially generated; a stamp 
with work factor 20 required mining roughly 2²⁰ ≈ 1 million argon2id 
evaluations.

Because argon2id is memory-hard (64 MB per evaluation), GPU-parallel attacks 
are expensive. Mining a high-quality stamp on a laptop takes seconds to 
minutes; generating many identities with meaningful stamps remains costly.

The argon2id parameters match the [block-level PoW parameters](security.md#proof-of-work-as-admission-control) used elsewhere in 
the system, allowing the same hardware cost model to apply. The application 
salt `sneakernet-idpow-v1` domain-separates identity stamps from block stamps 
so neither type is reusable as the other.

### Mining

Mining is a probabilistic search: generate a random 16-byte nonce, compute the 
argon2id hash, count leading zero bits, keep the best result found within a 
time budget. A sender can mine incrementally — each session can extend the 
best stamp found so far, since the input to argon2id is the stamp concatenated 
with the fixed public key.

There is no minimum required work factor for sending messages. A stamp with any 
number of bits is accepted. A stamp with zero bits is a valid stamp. Recipients 
and relays may choose to apply their own thresholds — the work factor is 
surfaced through the identity string so the receiver can decide what to trust.

### Verification

A receiver verifies a stamp by:
```
input = stamp ‖ pubkey
hash  = argon2id(input, salt="sneakernet-idpow-v1", ...)
bits  = leading_zero_bits(hash)
```

where `pubkey` is the `sender_pub` from the plaintext header. The stamp must 
match that specific public key — verification against any other key will 
produce a different hash and a different (lower) work factor.

Because argon2id is expensive, verification results are cached. Computing the 
work factor once per unique (stamp, pubkey) pair is sufficient.

### PoW gifts

A sender can mine a stamp for someone else's key and deliver it as a direct 
message. The content is a plain-text token:

```
snk-pow-gift:<stamp_b64url>
```

When the recipient's client detects this pattern in a message addressed to a 
local identity, it extracts the stamp, verifies the work factor against the 
relevant public key, and stores it if the work factor exceeds the current best. 
This lets a well-resourced node help a friend establish a better stamp without 
requiring the friend to run mining hardware themselves.

---

## Threading

Messages can reference prior messages to form conversations. The `thread_refs` 
field holds an eight-entry skip-list, where each entry is a 32-byte block ID or 
all-zeros if absent.

When composing a reply to a message with block ID `target` and thread_refs 
`prev`:

```
refs[0] = target         // direct reply target
refs[1] = prev[0]        // 1 step back
refs[2] = prev[1]        // 2 steps back
refs[3] = prev[2]        // 4 steps back
...
refs[k] = prev[k-1]      // 2^(k-1) steps back
```

This allows a reader to efficiently traverse long threads without requiring 
every intermediate message to be present. A client that has missed some blocks 
can still reconstruct partial thread structure from the skip-list references in 
messages it does have.

Thread refs are optional. A message with all-zero `thread_refs` is a new 
thread, not a reply.

---

## Anonymity

All anonymity properties described in [blocks.md § Distinguishability](blocks.md#distinguishability) apply here. The 
messaging layer adds:

- **Sender anonymity**: setting `sender_pub` to all-zeros suppresses 
attribution entirely. No public key is transmitted, no signature is present, 
and the recipient has no cryptographic basis for attributing the message to any 
identity.
- **Recipient anonymity**: the block format does not include a recipient field. 
The messaging layer adds none. No observer with access to the ciphertext can 
determine who a message was sent to.
- **Non-repudiation for signed messages**: a valid Ed25519 signature can only 
have been produced by the holder of the signing key. A recipient who decrypts a 
signed message can show the (plaintext, signature, public key) triple to a third 
party who can independently verify it. Signed Sneakernet messages are 
non-repudiable. If you need deniability, send anonymously.

Signing and identity strings serve usability within trusted relationships. They 
are not a surveillance surface for a passive observer — signed and unsigned 
messages are indistinguishable in ciphertext — but once decrypted, a signed 
message is attributable to its key holder.

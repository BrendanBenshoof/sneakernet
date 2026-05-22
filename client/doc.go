// Package client implements the receiver side of the sneakernet anonymous
// messaging protocol.
//
// # Anonymity model
//
// Every block stored in a sneakernet blockstore is indistinguishable from
// random bytes to anyone who does not hold the intended recipient's private
// key. There is no addressing header, no sender field, and no metadata that
// links a block to an identity. The only way to determine whether a block
// carries a message for you is to attempt decryption and check whether the
// result is a valid message.
//
// # Cryptographic scheme
//
// Each message is encrypted with a one-time ephemeral X25519 key pair:
//
//  1. The sender generates a fresh ephemeral key pair for every message.
//  2. ECDH(ephemeral_private, recipient_public) produces a shared secret.
//  3. SHA-256 of the shared secret becomes the XChaCha20-Poly1305 key.
//  4. The plaintext — magic header, 2-byte length, message, zero padding —
//     is always exactly 1976 bytes, hiding the true message length.
//  5. The 2048-byte block payload is: ephemeral_public (32 B) | nonce (24 B)
//     | ciphertext+tag (1992 B). All 2048 bytes appear random.
//
// Decryption fails with a generic error for any block not addressed to the
// holder of the private key. The 128-bit AEAD tag makes false positives
// cryptographically negligible.
//
// # Components
//
//   - [Keystore] — stores a named collection of X25519 identities, encrypted
//     at rest with Argon2id + XChaCha20-Poly1305. Load once at startup with
//     [LoadKeystore]; call [Keystore.Keys] to obtain keys for scraping.
//
//   - [Client] — scrapes new blocks from a [blockstore.Store], tries every
//     held key against each block, and persists hits to a [MessageStore].
//     Maintains a Unix-second watermark so successive [Client.Scrape] calls
//     only process blocks added since the previous run.
//
//   - [MessageStore] — SQLite-backed inbox. Deduplicates by block ID so
//     re-scanning blocks near the checkpoint boundary is always safe.
//
// # Typical usage
//
//	ks, err := client.LoadKeystore("keys.json", password)
//	bs, err := blockstore.OpenSQLite("blocks.db")
//	ms, err := client.OpenMessageStore("inbox.db")
//
//	c := client.New(bs, ms, ks.Keys()...)
//	n, err := c.Scrape(ctx)
package client

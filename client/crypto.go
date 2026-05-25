package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const (
	pubKeySize = 32 // X25519 public key
	nonceSize  = chacha20poly1305.NonceSizeX
	tagSize    = 16 // XChaCha20-Poly1305 auth tag

	ciphertextOffset = pubKeySize + nonceSize                              // 56
	plaintextSize    = blockstore.PayloadSize - ciphertextOffset - tagSize // 4024
)

// v1 format constants — kept for backward-compat decryption only.
var magicV1 = [4]byte{'S', 'N', 'K', 0x01}

const (
	v1MagicSize  = 4
	v1LenSize    = 2
	v1HeaderSize = v1MagicSize + v1LenSize // 6
	v1MaxContent = plaintextSize - v1HeaderSize
)

// channelSaltSize is the per-block random salt prepended to channel payloads.
const channelSaltSize = pubKeySize // 32

// ErrNotOurMessage is returned by tryDecrypt when a block is not addressed to us.
var ErrNotOurMessage = errors.New("client: not our message")

// EdPubToX25519 converts an Ed25519 public key to the equivalent X25519 public key
// via the birational map between the Edwards and Montgomery forms of Curve25519.
func EdPubToX25519(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}

// edPrivToX25519 derives the X25519 private key from an Ed25519 private key.
// Both algorithms hash the same 32-byte seed with SHA-512; the first 32 bytes
// (after clamping) are the scalar used for Diffie-Hellman.
func edPrivToX25519(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(edPriv.Seed())
	scalar := h[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return ecdh.X25519().NewPrivateKey(scalar)
}

// Encrypt encodes mp and encrypts it for recipientEdPub (anonymous — no signature).
func Encrypt(recipientEdPub ed25519.PublicKey, mp MessagePayload) (blockstore.Payload, error) {
	recipientPub, err := EdPubToX25519(recipientEdPub)
	if err != nil {
		return blockstore.Payload{}, err
	}
	plain, err := EncodePayload(mp)
	if err != nil {
		return blockstore.Payload{}, err
	}
	return encryptPlain(recipientPub, plain)
}

// EncryptSigned encodes mp, signs the plaintext with sigKey, then encrypts for recipientEdPub.
// mp.SenderPub must already be set to the Ed25519 public key corresponding to sigKey.
func EncryptSigned(recipientEdPub ed25519.PublicKey, mp MessagePayload, sigKey ed25519.PrivateKey) (blockstore.Payload, error) {
	recipientPub, err := EdPubToX25519(recipientEdPub)
	if err != nil {
		return blockstore.Payload{}, err
	}
	plain, err := EncodePayload(mp)
	if err != nil {
		return blockstore.Payload{}, err
	}
	SignPayload(&plain, sigKey)
	return encryptPlain(recipientPub, plain)
}

func encryptPlain(recipientPub *ecdh.PublicKey, plain [plaintextSize]byte) (blockstore.Payload, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return blockstore.Payload{}, err
	}
	shared, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return blockstore.Payload{}, err
	}
	key := sha256.Sum256(shared)

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return blockstore.Payload{}, err
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return blockstore.Payload{}, err
	}

	ct := aead.Seal(nil, nonce[:], plain[:], nil)

	var payload blockstore.Payload
	copy(payload[:pubKeySize], ephemeral.PublicKey().Bytes())
	copy(payload[pubKeySize:ciphertextOffset], nonce[:])
	copy(payload[ciphertextOffset:], ct)
	return payload, nil
}

// EncryptChannel encrypts mp into a fixed-size Payload using a symmetric channelKey.
// Anyone who knows the passphrase (and thus the channelKey) can decrypt it.
// The mp.Channel field is ignored (it is a local routing annotation, not wire data).
func EncryptChannel(channelKey [32]byte, mp MessagePayload) (blockstore.Payload, error) {
	plain, err := EncodePayload(mp)
	if err != nil {
		return blockstore.Payload{}, err
	}
	return encryptChannelPlain(channelKey, plain)
}

// EncryptChannelSigned encodes mp, signs the plaintext with sigKey, then encrypts with channelKey.
// mp.SenderPub must already be set to the Ed25519 public key corresponding to sigKey.
func EncryptChannelSigned(channelKey [32]byte, mp MessagePayload, sigKey ed25519.PrivateKey) (blockstore.Payload, error) {
	plain, err := EncodePayload(mp)
	if err != nil {
		return blockstore.Payload{}, err
	}
	SignPayload(&plain, sigKey)
	return encryptChannelPlain(channelKey, plain)
}

func encryptChannelPlain(channelKey [32]byte, plain [plaintextSize]byte) (blockstore.Payload, error) {
	var salt [channelSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return blockstore.Payload{}, err
	}

	blockKey := sha256.Sum256(append(channelKey[:], salt[:]...))

	aead, err := chacha20poly1305.NewX(blockKey[:])
	if err != nil {
		return blockstore.Payload{}, err
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return blockstore.Payload{}, err
	}

	ct := aead.Seal(nil, nonce[:], plain[:], nil)

	var payload blockstore.Payload
	copy(payload[:channelSaltSize], salt[:])
	copy(payload[channelSaltSize:ciphertextOffset], nonce[:])
	copy(payload[ciphertextOffset:], ct)
	return payload, nil
}

// tryDecryptChannel attempts to decrypt payload as a channel message using channelKey.
func tryDecryptChannel(channelKey [32]byte, payload blockstore.Payload) (MessagePayload, error) {
	blockKey := sha256.Sum256(append(channelKey[:], payload[:channelSaltSize]...))

	aead, err := chacha20poly1305.NewX(blockKey[:])
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}

	plainSlice, err := aead.Open(nil, payload[channelSaltSize:ciphertextOffset], payload[ciphertextOffset:], nil)
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}
	if len(plainSlice) != plaintextSize {
		return MessagePayload{}, ErrNotOurMessage
	}

	buf := [plaintextSize]byte(plainSlice)
	mp, err := DecodePayload(buf)
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}
	if !mp.IsAnonymous() && !VerifySignature(buf) {
		return MessagePayload{}, ErrNotOurMessage
	}
	return mp, nil
}

// tryDecrypt attempts to decrypt payload using the X25519 key derived from edPriv.
// Returns ErrNotOurMessage if the block was not addressed to us or is malformed.
// Handles both v1 (magic 0x01) and v2 (magic 0x02) formats.
func tryDecrypt(edPriv ed25519.PrivateKey, payload blockstore.Payload) (MessagePayload, error) {
	privKey, err := edPrivToX25519(edPriv)
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}

	ephPub, err := ecdh.X25519().NewPublicKey(payload[:pubKeySize])
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}
	shared, err := privKey.ECDH(ephPub)
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}
	key := sha256.Sum256(shared)

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}

	plain, err := aead.Open(nil, payload[pubKeySize:ciphertextOffset], payload[ciphertextOffset:], nil)
	if err != nil {
		return MessagePayload{}, ErrNotOurMessage
	}
	if len(plain) < 4 {
		return MessagePayload{}, ErrNotOurMessage
	}

	magic4 := [4]byte(plain[:4])

	if magic4 == MagicV2 {
		buf := [plaintextSize]byte(plain)
		mp, err := DecodePayload(buf)
		if err != nil {
			return MessagePayload{}, ErrNotOurMessage
		}
		// Reject messages that claim a sender but carry an invalid signature.
		if !mp.IsAnonymous() && !VerifySignature(buf) {
			return MessagePayload{}, ErrNotOurMessage
		}
		return mp, nil
	}

	// v1 backward-compat
	if magic4 == magicV1 {
		if len(plain) < v1HeaderSize {
			return MessagePayload{}, ErrNotOurMessage
		}
		msgLen := int(binary.LittleEndian.Uint16(plain[v1MagicSize:v1HeaderSize]))
		if msgLen > v1MaxContent || v1HeaderSize+msgLen > len(plain) {
			return MessagePayload{}, ErrNotOurMessage
		}
		content := make([]byte, msgLen)
		copy(content, plain[v1HeaderSize:v1HeaderSize+msgLen])
		return MessagePayload{
			MsgType:   MsgTypeText,
			FragTotal: 1,
			Content:   content,
		}, nil
	}

	return MessagePayload{}, ErrNotOurMessage
}

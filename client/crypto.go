package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

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

// ErrNotOurMessage is returned by tryDecrypt when a block is not addressed to us.
var ErrNotOurMessage = errors.New("client: not our message")

// GenerateKey creates a new X25519 private key.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// Encrypt encodes mp and encrypts it for recipientPub (anonymous — no signature).
func Encrypt(recipientPub *ecdh.PublicKey, mp MessagePayload) (blockstore.Payload, error) {
	plain, err := EncodePayload(mp)
	if err != nil {
		return blockstore.Payload{}, err
	}
	return encryptPlain(recipientPub, plain)
}

// EncryptSigned encodes mp, signs the plaintext with sigKey, then encrypts.
// mp.SenderPub must already be set to the Ed25519 public key corresponding to sigKey.
func EncryptSigned(recipientPub *ecdh.PublicKey, mp MessagePayload, sigKey ed25519.PrivateKey) (blockstore.Payload, error) {
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

// tryDecrypt attempts to decrypt payload using privKey.
// Returns ErrNotOurMessage if the block was not addressed to us or is malformed.
// Handles both v1 (magic 0x01) and v2 (magic 0x02) formats.
func tryDecrypt(privKey *ecdh.PrivateKey, payload blockstore.Payload) (MessagePayload, error) {
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

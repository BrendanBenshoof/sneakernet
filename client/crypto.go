package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const (
	pubKeySize  = 32 // X25519 public key
	nonceSize   = chacha20poly1305.NonceSizeX
	tagSize     = 16 // XChaCha20-Poly1305 auth tag
	magicSize   = 4
	lenSize     = 2

	ciphertextOffset = pubKeySize + nonceSize                                          // 56
	plaintextSize    = blockstore.PayloadSize - ciphertextOffset - tagSize             // 1976
	headerSize       = magicSize + lenSize                                             // 6
	maxMessageSize   = plaintextSize - headerSize                                      // 1970
)

var magic = [magicSize]byte{'S', 'N', 'K', 0x01}

// ErrNotOurMessage is returned by tryDecrypt when a block is not addressed to us.
var ErrNotOurMessage = errors.New("client: not our message")

// GenerateKey creates a new X25519 private key.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// Encrypt encodes msg into a fixed-size Payload addressed to recipientPub.
// The resulting payload is indistinguishable from random bytes to anyone
// who does not hold the corresponding private key.
func Encrypt(recipientPub *ecdh.PublicKey, msg []byte) (blockstore.Payload, error) {
	if len(msg) > maxMessageSize {
		return blockstore.Payload{}, errors.New("client: message too large")
	}

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

	var plain [plaintextSize]byte
	copy(plain[:magicSize], magic[:])
	binary.LittleEndian.PutUint16(plain[magicSize:], uint16(len(msg)))
	copy(plain[headerSize:], msg)
	// remaining bytes are zero padding — always encrypt the full buffer

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
func tryDecrypt(privKey *ecdh.PrivateKey, payload blockstore.Payload) ([]byte, error) {
	ephPub, err := ecdh.X25519().NewPublicKey(payload[:pubKeySize])
	if err != nil {
		return nil, ErrNotOurMessage
	}

	shared, err := privKey.ECDH(ephPub)
	if err != nil {
		return nil, ErrNotOurMessage
	}
	key := sha256.Sum256(shared)

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, ErrNotOurMessage
	}

	plain, err := aead.Open(nil, payload[pubKeySize:ciphertextOffset], payload[ciphertextOffset:], nil)
	if err != nil {
		return nil, ErrNotOurMessage
	}

	if len(plain) < headerSize || [magicSize]byte(plain[:magicSize]) != magic {
		return nil, ErrNotOurMessage
	}

	msgLen := int(binary.LittleEndian.Uint16(plain[magicSize:headerSize]))
	if msgLen > maxMessageSize {
		return nil, ErrNotOurMessage
	}

	out := make([]byte, msgLen)
	copy(out, plain[headerSize:headerSize+msgLen])
	return out, nil
}

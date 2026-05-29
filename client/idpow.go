package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"math/bits"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	idPowArgonTime    uint32 = 1
	idPowArgonMemory  uint32 = 64 * 1024 // 64 MB
	idPowArgonThreads uint8  = 1
	idPowArgonKeyLen  uint32 = 32
	idPowStampSize           = 16
)

var idPowSalt = []byte("sneakernet-idpow-v1")

// PowGiftPrefix is the content prefix for an identity PoW gift message.
const PowGiftPrefix = "snk-pow-gift:"

// FormatPowGift returns the content string for a PoW gift DM.
func FormatPowGift(stamp []byte) string {
	return PowGiftPrefix + base64.RawURLEncoding.EncodeToString(stamp)
}

// ParsePowGift detects and decodes a PoW gift from message content.
// Returns the stamp bytes and true on success.
func ParsePowGift(content []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(content))
	if !strings.HasPrefix(s, PowGiftPrefix) {
		return nil, false
	}
	stamp, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s[len(PowGiftPrefix):]))
	if err != nil || len(stamp) == 0 {
		return nil, false
	}
	return stamp, true
}

// ParseSnkStamp extracts the identity PoW stamp from the first line of message
// content if it contains a valid snk: header for senderPub.
// Returns the stamp and its work factor; returns nil, 0 if absent or unverifiable.
func ParseSnkStamp(content []byte, senderPub [32]byte) ([]byte, int) {
	line := content
	if nl := bytes.IndexByte(content, '\n'); nl >= 0 {
		line = content[:nl]
	}
	// snk:name/pubkeyB64url [stampB64url]
	spaceIdx := bytes.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return nil, 0
	}
	snkPart := string(line[:spaceIdx])
	stampStr := strings.TrimSpace(string(line[spaceIdx+1:]))
	slashIdx := strings.LastIndex(snkPart, "/")
	if slashIdx < 0 || !strings.HasPrefix(snkPart, "snk:") {
		return nil, 0
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(snkPart[slashIdx+1:])
	if err != nil || len(pubBytes) != 32 || !bytes.Equal(pubBytes, senderPub[:]) {
		return nil, 0
	}
	stamp, err := base64.RawURLEncoding.DecodeString(stampStr)
	if err != nil || len(stamp) == 0 {
		return nil, 0
	}
	return stamp, IdentityWorkFactor(stamp, senderPub)
}

// IdentityWorkFactor returns the number of leading zero bits in
// argon2id(stamp || pubkey, salt="sneakernet-idpow-v1").
func IdentityWorkFactor(stamp []byte, pubkey [32]byte) int {
	input := make([]byte, len(stamp)+32)
	copy(input, stamp)
	copy(input[len(stamp):], pubkey[:])
	hash := argon2.IDKey(input, idPowSalt, idPowArgonTime, idPowArgonMemory, idPowArgonThreads, idPowArgonKeyLen)
	return idPowLeadingZeroBits(hash)
}

// MineIdentityPoW mines random 16-byte stamps for the given duration, returning
// the stamp with the highest work factor found. Returns early with an error if
// ctx is cancelled before the duration elapses. If seed is a valid 16-byte
// stamp it is used as the initial best, so the result is always >= seed's bits.
func MineIdentityPoW(ctx context.Context, pubkey [32]byte, duration time.Duration, seed []byte) ([]byte, int, error) {
	best := make([]byte, idPowStampSize)
	var bestBits int
	if len(seed) == idPowStampSize {
		copy(best, seed)
		bestBits = IdentityWorkFactor(best, pubkey)
	} else {
		if _, err := rand.Read(best); err != nil {
			return nil, 0, err
		}
		bestBits = IdentityWorkFactor(best, pubkey)
	}

	deadline := time.After(duration)
	stamp := make([]byte, idPowStampSize)
	for {
		select {
		case <-ctx.Done():
			return best, bestBits, ctx.Err() // return best-so-far; caller decides whether to use it
		case <-deadline:
			return best, bestBits, nil
		default:
		}
		if _, err := rand.Read(stamp); err != nil {
			return best, bestBits, err
		}
		if wf := IdentityWorkFactor(stamp, pubkey); wf > bestBits {
			bestBits = wf
			copy(best, stamp)
		}
	}
}

func idPowLeadingZeroBits(b []byte) int {
	count := 0
	for _, v := range b {
		lz := bits.LeadingZeros8(v)
		count += lz
		if lz < 8 {
			break
		}
	}
	return count
}

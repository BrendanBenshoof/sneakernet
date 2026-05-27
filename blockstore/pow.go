package blockstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"math/bits"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // 64 MB
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
)

// fixed application salt; changing this invalidates all stored work factors
var argonSalt = []byte("sneakernet-pow-v1")

// ComputeID returns sha256(payload).
func ComputeID(payload Payload) ID {
	return sha256.Sum256(payload[:])
}

// WorkFactor counts leading zero bits in argon2id(stamp ‖ payload).
func WorkFactor(stamp Stamp, payload Payload) int {
	input := make([]byte, StampSize+PayloadSize)
	copy(input[:StampSize], stamp[:])
	copy(input[StampSize:], payload[:])
	hash := argon2.IDKey(input, argonSalt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return leadingZeroBits(hash)
}

// MineStamp searches for a Stamp giving WorkFactor >= target for payload.
// Tries random stamps until one succeeds or ctx is cancelled.
// Returns immediately with a zero stamp when target <= 0.
func MineStamp(ctx context.Context, payload Payload, target int) (Stamp, int, error) {
	var stamp Stamp
	if target <= 0 {
		return stamp, WorkFactor(stamp, payload), nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return stamp, 0, err
		}
		if _, err := rand.Read(stamp[:]); err != nil {
			return stamp, 0, err
		}
		if wf := WorkFactor(stamp, payload); wf >= target {
			return stamp, wf, nil
		}
	}
}

func leadingZeroBits(b []byte) int {
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

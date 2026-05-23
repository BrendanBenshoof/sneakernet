package relay

import (
	"encoding/binary"
	"fmt"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const (
	bloomBits  = 1 << 16 // 65 536 bits
	bloomBytes = bloomBits / 8 // 8 192 bytes
)

// Bloom is a fixed-size Bloom filter tuned for blockstore.IDs.
// Uses 3 hash functions at byte offsets 0, 8, 16 of the ID.
// False-positive rate ≈ 0.4 % at 1 000 items, ≈ 3.5 % at 5 000.
type Bloom struct {
	bits [bloomBytes]byte
}

func (b *Bloom) slot(id blockstore.ID, byteOffset int) uint32 {
	return binary.BigEndian.Uint32(id[byteOffset:byteOffset+4]) & (bloomBits - 1)
}

// Add inserts id into the filter.
func (b *Bloom) Add(id blockstore.ID) {
	for _, off := range []int{0, 8, 16} {
		s := b.slot(id, off)
		b.bits[s>>3] |= 1 << (s & 7)
	}
}

// Has reports whether id is probably in the filter (may false-positive, never false-negative).
func (b *Bloom) Has(id blockstore.ID) bool {
	for _, off := range []int{0, 8, 16} {
		s := b.slot(id, off)
		if b.bits[s>>3]&(1<<(s&7)) == 0 {
			return false
		}
	}
	return true
}

// Bytes returns the raw 8 192-byte filter payload.
func (b *Bloom) Bytes() []byte {
	out := make([]byte, bloomBytes)
	copy(out, b.bits[:])
	return out
}

// BloomFromBytes reconstructs a filter from raw bytes.
func BloomFromBytes(data []byte) (*Bloom, error) {
	if len(data) != bloomBytes {
		return nil, fmt.Errorf("relay: bloom: expected %d bytes, got %d", bloomBytes, len(data))
	}
	var b Bloom
	copy(b.bits[:], data)
	return &b, nil
}

// BloomOfStore builds a Bloom filter containing every ID currently in store.
func BloomOfStore(store blockstore.Store) (*Bloom, error) {
	ids, err := store.ListIDs()
	if err != nil {
		return nil, err
	}
	var b Bloom
	for _, id := range ids {
		b.Add(id)
	}
	return &b, nil
}

package relay

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const (
	bloomBits  = 1 << 16 // 65 536 bits
	bloomBytes = bloomBits / 8 // 8 192 bytes

	// maxBloomPow is the highest PoW level tracked in the filter.
	// Blocks with work_factor > maxBloomPow are treated as maxBloomPow.
	maxBloomPow = 16
)

// Bloom is a fixed-size Bloom filter that encodes both block identity and
// proof-of-work level. Add(id, wf) sets bits at levels 0..wf, so Has(id, k)
// returns true iff the filter contains id at work_factor >= k.
type Bloom struct {
	bits [bloomBytes]byte
}

// slot returns the bit index for (id, level) using bytes at byteOffset.
// The level is mixed in so that the same id at different levels maps to
// different slots.
func (b *Bloom) slot(id blockstore.ID, byteOffset, level int) uint32 {
	v := binary.BigEndian.Uint32(id[byteOffset : byteOffset+4])
	v ^= uint32(level) * 2654435761 // Knuth multiplicative hash
	return v & (bloomBits - 1)
}

// Add inserts id into the filter at all levels from 0 up to min(wf, maxBloomPow).
func (b *Bloom) Add(id blockstore.ID, wf int) {
	if wf > maxBloomPow {
		wf = maxBloomPow
	}
	for level := 0; level <= wf; level++ {
		for _, off := range []int{0, 8, 16} {
			s := b.slot(id, off, level)
			b.bits[s>>3] |= 1 << (s & 7)
		}
	}
}

// Has reports whether id is probably present at work_factor >= wf.
// Never false-negative: if Add(id, k) was called with k >= wf, Has returns true.
func (b *Bloom) Has(id blockstore.ID, wf int) bool {
	if wf > maxBloomPow {
		wf = maxBloomPow
	}
	for _, off := range []int{0, 8, 16} {
		s := b.slot(id, off, wf)
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

// BloomOfStore builds a Bloom filter containing every non-expired block in
// store, with each entry reflecting its actual work_factor.
func BloomOfStore(store blockstore.Store) (*Bloom, error) {
	var b Bloom
	pageToken := ""
	for {
		next, refs, err := store.ListBlocks(pageToken, 500, 0, time.Time{})
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			b.Add(ref.ID, ref.WorkFactor)
		}
		if next == "" {
			break
		}
		pageToken = next
	}
	return &b, nil
}

package blockstore

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	PayloadSize = 2048
	StampSize   = 4
	IDSize      = 32

	// BaseTTL is the minimum block lifetime (work_factor == 0).
	BaseTTL = 24 * time.Hour
)

var ErrNotFound = errors.New("blockstore: block not found")

type ID = [IDSize]byte
type Stamp = [StampSize]byte
type Payload = [PayloadSize]byte

// BlockRef is a lightweight handle returned by ListBlocks.
type BlockRef struct {
	WorkFactor int
	ID         ID
}

// Store is the interface every blockstore backend must satisfy.
type Store interface {
	Put(stamp Stamp, payload Payload) (ID, error)
	Get(id ID) (Stamp, Payload, error)
	Has(id ID) (bool, error)
	ListIDs() ([]ID, error)
	// ListBlocks returns up to limit blocks with work_factor >= powFloor and
	// created_at >= since, ordered by (created_at, id). Pass an empty
	// pageToken to start from the beginning. The returned nextToken is empty
	// when no further pages exist.
	ListBlocks(pageToken string, limit int, powFloor int, since time.Time) (nextToken string, blocks []BlockRef, err error)
	Prune() (int, error)
	Close() error
}

// pageTokenCursor encodes/decodes the opaque pagination cursor.
// Layout: 8-byte big-endian unix timestamp ‖ 32-byte block ID (40 bytes total).

type cursor struct {
	createdAt int64
	id        ID
}

func encodeCursor(c cursor) string {
	var buf [8 + IDSize]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(c.createdAt))
	copy(buf[8:], c.id[:])
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func decodeCursor(token string) (cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) != 8+IDSize {
		return cursor{}, fmt.Errorf("blockstore: invalid page token")
	}
	var c cursor
	c.createdAt = int64(binary.BigEndian.Uint64(b[:8]))
	copy(c.id[:], b[8:])
	return c, nil
}

// TTLFromWorkFactor maps leading-zero bit count to a block lifetime.
// Linear for now: BaseTTL × (wf + 1).
func TTLFromWorkFactor(wf int) time.Duration {
	if wf < 0 {
		wf = 0
	}
	return BaseTTL * time.Duration(wf+1)
}

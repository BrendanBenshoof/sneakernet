package blockstore_test

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

func openFlatFile(t *testing.T) (*blockstore.FlatFileStore, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "blockstore-flat-*")
	if err != nil {
		t.Fatal(err)
	}
	s, err := blockstore.OpenFlatFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); os.RemoveAll(dir) })
	return s, dir
}

// writeFlatBlock writes a block file directly, bypassing Put, so we can
// control the expiresAt field for eviction-order tests.
func writeFlatBlock(t *testing.T, root string, id blockstore.ID, expiresAt int64) {
	t.Helper()
	h := hex.EncodeToString(id[:])
	dir := filepath.Join(root, h[:2], h[2:4])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Header: stamp[4] | wf[4] | created_at[8] | expires_at[8]
	var buf [4 + 4 + 8 + 8 + blockstore.PayloadSize]byte
	binary.BigEndian.PutUint64(buf[8:16], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint64(buf[16:24], uint64(expiresAt))
	if err := os.WriteFile(filepath.Join(dir, h), buf[:], 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFlatFilePruneIsNoOp(t *testing.T) {
	s, _ := openFlatFile(t)
	var stamp blockstore.Stamp
	var p blockstore.Payload
	p[0] = 1
	s.Put(stamp, p, blockstore.TagPhysical)

	n, err := s.Prune()
	if err != nil {
		t.Fatal("Prune:", err)
	}
	if n != 0 {
		t.Errorf("Prune: expected 0 removals, got %d", n)
	}
	// Block must still be retrievable.
	id := blockstore.ComputeID(p)
	if _, _, err := s.Get(id); err != nil {
		t.Errorf("Get after Prune: %v", err)
	}
}

func TestFlatFileEvict(t *testing.T) {
	s, _ := openFlatFile(t)
	var stamp blockstore.Stamp
	for i := 0; i < 3; i++ {
		var p blockstore.Payload
		p[0] = byte(i + 1)
		if _, err := s.Put(stamp, p, blockstore.TagPhysical); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.Evict(2)
	if err != nil {
		t.Fatal("Evict:", err)
	}
	if n != 2 {
		t.Errorf("expected 2 evicted, got %d", n)
	}

	ids, err := s.ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Errorf("expected 1 block remaining, got %d", len(ids))
	}
}

func TestFlatFileEvictOrder(t *testing.T) {
	s, root := openFlatFile(t)

	// Write three blocks directly with controlled expiresAt values.
	// Block A expires soonest — should be evicted first.
	// Block C expires latest — should survive.
	now := time.Now().Unix()
	var idA, idB, idC blockstore.ID
	idA[0] = 0xAA
	idB[0] = 0xBB
	idC[0] = 0xCC

	writeFlatBlock(t, root, idA, now+100)
	writeFlatBlock(t, root, idB, now+200)
	writeFlatBlock(t, root, idC, now+300)

	n, err := s.Evict(1)
	if err != nil {
		t.Fatal("Evict:", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 evicted, got %d", n)
	}

	// idA must be gone; idB and idC must remain.
	if ok, _ := s.Has(idA); ok {
		t.Error("idA (soonest expiry) should have been evicted but is still present")
	}
	if ok, _ := s.Has(idB); !ok {
		t.Error("idB should still be present")
	}
	if ok, _ := s.Has(idC); !ok {
		t.Error("idC should still be present")
	}
}

func TestFlatFileStorageLimit(t *testing.T) {
	s, _ := openFlatFile(t)
	const fileSize = 4 + 4 + 8 + 8 + blockstore.PayloadSize // flatHeaderSize + PayloadSize
	s.WithStorageLimit(int64(fileSize * 2)) // room for 2 blocks

	var stamp blockstore.Stamp
	for i := 0; i < 4; i++ {
		var p blockstore.Payload
		p[0] = byte(i + 1)
		if _, err := s.Put(stamp, p, blockstore.TagPhysical); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := s.ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	// Should have evicted down to at most 2 blocks (limit enforced per-put).
	if len(ids) > 2 {
		t.Errorf("storage limit not enforced: %d blocks remain, expected ≤ 2", len(ids))
	}
}

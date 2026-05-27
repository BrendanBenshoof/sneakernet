package blockstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

func TestBuildAndOpenIndex(t *testing.T) {
	dir, err := os.MkdirTemp("", "flatstore-index-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	store, err := blockstore.OpenFlatFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var stamp blockstore.Stamp
	ids := make([]blockstore.ID, 5)
	for i := range ids {
		var p blockstore.Payload
		p[0] = byte(i + 1)
		id, err := store.Put(stamp, p, blockstore.TagPhysical)
		if err != nil {
			t.Fatal("Put:", err)
		}
		ids[i] = id
	}

	if err := blockstore.BuildIndex(dir); err != nil {
		t.Fatal("BuildIndex:", err)
	}

	idx, err := blockstore.OpenIndex(filepath.Join(dir, "index.bin"))
	if err != nil {
		t.Fatal("OpenIndex:", err)
	}

	for _, id := range ids {
		if !idx.Has(id) {
			t.Errorf("Has(%x) = false, want true", id)
		}
	}

	var missing blockstore.ID
	missing[0] = 0xFF
	if idx.Has(missing) {
		t.Error("Has(missing) = true, want false")
	}

	recs := idx.Records()
	if len(recs) != 5 {
		t.Errorf("Records() returned %d, want 5", len(recs))
	}
}

func TestBuildShardedIndex(t *testing.T) {
	dir, err := os.MkdirTemp("", "flatstore-sharded-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	store, err := blockstore.OpenFlatFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var stamp blockstore.Stamp
	inserted := make(map[blockstore.ID]bool)
	for i := 0; i < 10; i++ {
		var p blockstore.Payload
		p[0] = byte(i + 1)
		id, err := store.Put(stamp, p, blockstore.TagPhysical)
		if err != nil {
			t.Fatal("Put:", err)
		}
		inserted[id] = true
	}

	// Force sharded mode by calling the exported helper directly.
	if err := blockstore.BuildShardedIndex(dir); err != nil {
		t.Fatal("BuildShardedIndex:", err)
	}

	// Verify every inserted block appears in its shard.
	found := 0
	for id := range inserted {
		shardPath := filepath.Join(dir, "index", blockstore.ShardName(id))
		idx, err := blockstore.OpenIndex(shardPath)
		if err != nil {
			t.Fatalf("OpenIndex(%s): %v", shardPath, err)
		}
		if idx.Has(id) {
			found++
		}
	}
	if found != len(inserted) {
		t.Errorf("found %d/%d inserted blocks in shards", found, len(inserted))
	}
}

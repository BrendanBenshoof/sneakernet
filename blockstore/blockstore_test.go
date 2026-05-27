package blockstore_test

import (
	"os"
	"testing"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// openStore returns one Store per backend under test.
func openStores(t *testing.T) map[string]blockstore.Store {
	t.Helper()

	// BadgerDB
	badgerDir, err := os.MkdirTemp("", "blockstore-badger-*")
	if err != nil {
		t.Fatal(err)
	}
	badgerStore, err := blockstore.OpenBadger(badgerDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { badgerStore.Close(); os.RemoveAll(badgerDir) })

	// FlatFile
	flatDir, err := os.MkdirTemp("", "blockstore-flat-*")
	if err != nil {
		t.Fatal(err)
	}
	flatStore, err := blockstore.OpenFlatFile(flatDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { flatStore.Close(); os.RemoveAll(flatDir) })

	return map[string]blockstore.Store{
		"badger":   badgerStore,
		"flatfile": flatStore,
	}
}

func TestPutGet(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var payload blockstore.Payload
			payload[0] = 0xDE
			payload[1] = 0xAD

			id, err := s.Put(stamp, payload, blockstore.TagPhysical)
			if err != nil {
				t.Fatal("Put:", err)
			}
			gotStamp, gotPayload, err := s.Get(id)
			if err != nil {
				t.Fatal("Get:", err)
			}
			if gotStamp != stamp {
				t.Errorf("stamp mismatch: got %x want %x", gotStamp, stamp)
			}
			if gotPayload != payload {
				t.Error("payload mismatch")
			}
		})
	}
}

func TestHas(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var payload blockstore.Payload
			id, _ := s.Put(stamp, payload, blockstore.TagPhysical)

			ok, err := s.Has(id)
			if err != nil || !ok {
				t.Fatalf("Has after Put: got %v, %v", ok, err)
			}
			var missing blockstore.ID
			missing[0] = 0xFF
			ok, err = s.Has(missing)
			if err != nil || ok {
				t.Fatalf("Has for missing block: got %v, %v", ok, err)
			}
		})
	}
}

func TestListIDs(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var p1, p2 blockstore.Payload
			p1[0] = 1
			p2[0] = 2

			id1, _ := s.Put(stamp, p1, blockstore.TagPhysical)
			id2, _ := s.Put(stamp, p2, blockstore.TagPhysical)

			ids, err := s.ListIDs()
			if err != nil {
				t.Fatal("ListIDs:", err)
			}
			if len(ids) != 2 {
				t.Fatalf("expected 2 IDs, got %d", len(ids))
			}
			set := map[blockstore.ID]bool{id1: true, id2: true}
			for _, id := range ids {
				if !set[id] {
					t.Errorf("unexpected id in list: %x", id)
				}
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var id blockstore.ID
			_, _, err := s.Get(id)
			if err != blockstore.ErrNotFound {
				t.Errorf("expected ErrNotFound, got %v", err)
			}
		})
	}
}

func TestIDIsPayloadHash(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var payload blockstore.Payload
			payload[100] = 42

			expected := blockstore.ComputeID(payload)
			id, err := s.Put(stamp, payload, blockstore.TagPhysical)
			if err != nil {
				t.Fatal(err)
			}
			if id != expected {
				t.Errorf("id %x != sha256(payload) %x", id, expected)
			}
		})
	}
}

func TestListBlocksPagination(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			for i := 0; i < 5; i++ {
				var p blockstore.Payload
				p[0] = byte(i + 1)
				if _, err := s.Put(stamp, p, blockstore.TagPhysical); err != nil {
					t.Fatal("Put:", err)
				}
			}

			var got []blockstore.BlockRef
			token := ""
			for {
				next, page, err := s.ListBlocks(token, 2, 0, time.Time{})
				if err != nil {
					t.Fatal("ListBlocks:", err)
				}
				got = append(got, page...)
				token = next
				if token == "" {
					break
				}
			}

			if len(got) != 5 {
				t.Fatalf("expected 5 total blocks across pages, got %d", len(got))
			}
			seen := make(map[blockstore.ID]bool)
			for _, ref := range got {
				if seen[ref.ID] {
					t.Errorf("duplicate ID %x in paginated results", ref.ID)
				}
				seen[ref.ID] = true
			}
		})
	}
}

func TestListBlocksPOWFloor(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var p blockstore.Payload
			s.Put(stamp, p, blockstore.TagPhysical)

			_, refs, err := s.ListBlocks("", 100, 999, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			if len(refs) != 0 {
				t.Errorf("expected 0 results for impossible powFloor, got %d", len(refs))
			}
		})
	}
}

func TestListBlocksSinceFilter(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			var stamp blockstore.Stamp
			var p blockstore.Payload
			p[0] = 1
			s.Put(stamp, p, blockstore.TagPhysical)

			future := time.Now().Add(time.Hour)
			_, refs, err := s.ListBlocks("", 100, 0, future)
			if err != nil {
				t.Fatal(err)
			}
			if len(refs) != 0 {
				t.Errorf("expected 0 results for future sinceTime, got %d", len(refs))
			}
		})
	}
}

func TestListBlocksInvalidToken(t *testing.T) {
	for name, s := range openStores(t) {
		t.Run(name, func(t *testing.T) {
			_, _, err := s.ListBlocks("not-a-valid-token!!", 10, 0, time.Time{})
			if err == nil {
				t.Error("expected error for invalid page token, got nil")
			}
		})
	}
}

func TestWorkFactor(t *testing.T) {
	var stamp blockstore.Stamp
	var payload blockstore.Payload
	wf := blockstore.WorkFactor(stamp, payload)
	t.Logf("work_factor for zero stamp/payload: %d leading zero bits", wf)
	if wf < 0 {
		t.Error("work factor must be non-negative")
	}
}

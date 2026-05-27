package blockstore_test

import (
	"os"
	"sort"
	"testing"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

func openBadger(t *testing.T) *blockstore.BadgerStore {
	t.Helper()
	dir, err := os.MkdirTemp("", "blockstore-badger-*")
	if err != nil {
		t.Fatal(err)
	}
	s, err := blockstore.OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); os.RemoveAll(dir) })
	return s
}

func TestBadgerMedianWorkFactorEmpty(t *testing.T) {
	s := openBadger(t)
	if err := s.RefreshMedian(); err != nil {
		t.Fatal(err)
	}
	wf, err := s.MedianWorkFactor()
	if err != nil {
		t.Fatal(err)
	}
	if wf != 0 {
		t.Errorf("empty store: got median %d, want 0", wf)
	}
}

func TestBadgerMedianWorkFactor(t *testing.T) {
	s := openBadger(t)
	var stamp blockstore.Stamp
	var wfs []int
	for i := 0; i < 5; i++ {
		var p blockstore.Payload
		p[0] = byte(i + 1)
		if _, err := s.Put(stamp, p, blockstore.TagPhysical); err != nil {
			t.Fatal(err)
		}
		wfs = append(wfs, blockstore.WorkFactor(stamp, p))
	}

	if err := s.RefreshMedian(); err != nil {
		t.Fatal(err)
	}
	got, err := s.MedianWorkFactor()
	if err != nil {
		t.Fatal(err)
	}

	sort.Ints(wfs)
	want := wfs[len(wfs)/2]
	if got != want {
		t.Errorf("median: got %d, want %d (sorted wfs: %v)", got, want, wfs)
	}
}

func TestBadgerEvictWritesTombstone(t *testing.T) {
	s := openBadger(t)
	var stamp blockstore.Stamp
	var payload blockstore.Payload
	payload[0] = 0xBE

	id, err := s.Put(stamp, payload, blockstore.TagPhysical)
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.Evict(1)
	if err != nil {
		t.Fatal("Evict:", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 evicted, got %d", n)
	}

	// Get must return ErrNotFound.
	if _, _, err := s.Get(id); err != blockstore.ErrNotFound {
		t.Errorf("Get after evict: want ErrNotFound, got %v", err)
	}
	// Has returns true because the tombstone is present.
	ok, err := s.Has(id)
	if err != nil {
		t.Fatal("Has:", err)
	}
	if !ok {
		t.Error("Has after evict: want true (tombstone), got false")
	}
}

func TestBadgerEvictEmpty(t *testing.T) {
	s := openBadger(t)
	n, err := s.Evict(5)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 evicted from empty store, got %d", n)
	}
}

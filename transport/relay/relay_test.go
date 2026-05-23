package relay_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/transport/relay"
)

func newStore(t *testing.T) blockstore.Store {
	t.Helper()
	s, err := blockstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTestPair(t *testing.T, powFloor int) (blockstore.Store, *relay.Client) {
	t.Helper()
	store := newStore(t)
	srv := relay.NewServer(store, powFloor)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	client := relay.NewClient(ts.URL)
	return store, client
}

// makeBlock returns a stamp+payload that achieves at least zero leading zero bits
// (any non-zero stamp works for powFloor==0 tests).
func makeBlock(seed byte) (blockstore.Stamp, blockstore.Payload) {
	var stamp blockstore.Stamp
	var payload blockstore.Payload
	stamp[0] = seed
	payload[0] = seed
	return stamp, payload
}

func TestGetPowLimit(t *testing.T) {
	_, client := newTestPair(t, 3)
	floor, err := client.GetPowLimit(context.Background())
	if err != nil {
		t.Fatalf("GetPowLimit: %v", err)
	}
	if floor != 3 {
		t.Fatalf("expected pow_floor=3, got %d", floor)
	}
}

func TestPutAndGet(t *testing.T) {
	_, client := newTestPair(t, 0)
	stamp, payload := makeBlock(42)

	id, err := client.Put(context.Background(), stamp, payload)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	gotStamp, gotPayload, err := client.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotStamp != stamp {
		t.Error("stamp mismatch")
	}
	if gotPayload != payload {
		t.Error("payload mismatch")
	}
}

func TestGetNotFound(t *testing.T) {
	_, client := newTestPair(t, 0)
	var id blockstore.ID
	_, _, err := client.Get(context.Background(), id)
	if err != blockstore.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPutRejectedBelowPowFloor(t *testing.T) {
	// Use a very high powFloor that no random block will satisfy.
	_, client := newTestPair(t, 255)
	stamp, payload := makeBlock(1)
	_, err := client.Put(context.Background(), stamp, payload)
	if err == nil {
		t.Fatal("expected error for insufficient PoW, got nil")
	}
}

func TestDelta(t *testing.T) {
	_, client := newTestPair(t, 0)
	localStore := newStore(t) // separate local store, not the relay's backing store

	// Put two blocks on the relay.
	stamp1, payload1 := makeBlock(1)
	stamp2, payload2 := makeBlock(2)
	id1, _ := client.Put(context.Background(), stamp1, payload1)
	id2, _ := client.Put(context.Background(), stamp2, payload2)

	// Local store has only block 1.
	localStore.Put(stamp1, payload1)

	bloom, err := relay.BloomOfStore(localStore)
	if err != nil {
		t.Fatalf("BloomOfStore: %v", err)
	}

	ids, err := client.Delta(context.Background(), bloom, 0, time.Time{})
	if err != nil {
		t.Fatalf("Delta: %v", err)
	}

	// Delta should return id2 but not id1.
	found1, found2 := false, false
	for _, id := range ids {
		if id == id1 {
			found1 = true
		}
		if id == id2 {
			found2 = true
		}
	}
	if found1 {
		t.Error("Delta returned id1 which is already in local bloom")
	}
	if !found2 {
		t.Error("Delta did not return id2 which is missing locally")
	}
}

func TestDeltaEmptyResult(t *testing.T) {
	_, client := newTestPair(t, 0)
	localStore := newStore(t)
	stamp, payload := makeBlock(7)
	client.Put(context.Background(), stamp, payload)

	// Local store has the same block.
	localStore.Put(stamp, payload)

	bloom, _ := relay.BloomOfStore(localStore)
	ids, err := client.Delta(context.Background(), bloom, 0, time.Time{})
	if err != nil {
		t.Fatalf("Delta: %v", err)
	}
	// May still return 0 or a false-positive; as long as no error and not panicking.
	_ = ids
}

func TestPull(t *testing.T) {
	remoteStore, client := newTestPair(t, 0)
	localStore := newStore(t)

	// Put blocks on the relay directly.
	stamp1, payload1 := makeBlock(10)
	stamp2, payload2 := makeBlock(20)
	remoteStore.Put(stamp1, payload1)
	remoteStore.Put(stamp2, payload2)

	n, err := client.Pull(context.Background(), localStore, 0, time.Time{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 blocks pulled, got %d", n)
	}

	// Second pull should find nothing new.
	n, err = client.Pull(context.Background(), localStore, 0, time.Time{})
	if err != nil {
		t.Fatalf("Pull (second): %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 blocks on second pull, got %d", n)
	}
}

func TestPush(t *testing.T) {
	_, client := newTestPair(t, 0)
	localStore := newStore(t)

	stamp1, payload1 := makeBlock(30)
	stamp2, payload2 := makeBlock(40)
	localStore.Put(stamp1, payload1)
	localStore.Put(stamp2, payload2)

	n, err := client.Push(context.Background(), localStore, 0, time.Time{})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 blocks pushed, got %d", n)
	}

	// Verify the relay now has them.
	id1 := blockstore.ComputeID(payload1)
	id2 := blockstore.ComputeID(payload2)
	_, _, err = client.Get(context.Background(), id1)
	if err != nil {
		t.Fatalf("Get id1 after push: %v", err)
	}
	_, _, err = client.Get(context.Background(), id2)
	if err != nil {
		t.Fatalf("Get id2 after push: %v", err)
	}
}

func TestBloomNoFalseNegatives(t *testing.T) {
	var b relay.Bloom
	ids := make([]blockstore.ID, 100)
	for i := range ids {
		ids[i][0] = byte(i)
		ids[i][1] = byte(i >> 8)
		b.Add(ids[i])
	}
	for _, id := range ids {
		if !b.Has(id) {
			t.Errorf("false negative for id %x", id)
		}
	}
}

func TestBloomFromBytes(t *testing.T) {
	var b relay.Bloom
	var id blockstore.ID
	id[0] = 0xAB
	b.Add(id)

	data := b.Bytes()
	b2, err := relay.BloomFromBytes(data)
	if err != nil {
		t.Fatalf("BloomFromBytes: %v", err)
	}
	if !b2.Has(id) {
		t.Error("round-tripped bloom lost the inserted id")
	}

	_, err = relay.BloomFromBytes([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for wrong-size bytes")
	}
}

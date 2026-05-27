package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/transport/relay"
)

func newStore(t *testing.T) blockstore.Store {
	t.Helper()
	s, err := blockstore.OpenBadger(t.TempDir())
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
	// Empty BadgerDB store: median=0, so server returns median-1 = -1.
	_, client := newTestPair(t, 3)
	floor, err := client.GetPowLimit(context.Background())
	if err != nil {
		t.Fatalf("GetPowLimit: %v", err)
	}
	if floor != -1 {
		t.Fatalf("expected pow_floor=-1 for empty store, got %d", floor)
	}
}

func TestGetPowLimitMedian(t *testing.T) {
	dir, err := os.MkdirTemp("", "relay-badger-*")
	if err != nil {
		t.Fatal(err)
	}
	// capacity=10 blocks, halfCapacity=5; store 8 so the floor is non-zero.
	const blockSize = 4113 // blockValHeaderSize(17) + PayloadSize(4096)
	store, err := blockstore.OpenBadger(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.WithStorageLimit(int64(10 * blockSize))
	t.Cleanup(func() { store.Close(); os.RemoveAll(dir) })

	srv := relay.NewServer(store, 0)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	client := relay.NewClient(ts.URL)

	var stamp blockstore.Stamp
	var wfs []int
	for i := 0; i < 8; i++ { // 8 > halfCapacity(5)
		var p blockstore.Payload
		p[0] = byte(i + 1)
		store.Put(stamp, p, blockstore.TagPhysical)
		wfs = append(wfs, blockstore.WorkFactor(stamp, p))
	}
	sort.Ints(wfs)
	want := wfs[5] // wfs[halfCapacity] where halfCapacity = capacity/2 = 10/2 = 5

	if err := store.RefreshMedian(); err != nil {
		t.Fatal("RefreshMedian:", err)
	}

	floor, err := client.GetPowLimit(context.Background())
	if err != nil {
		t.Fatalf("GetPowLimit: %v", err)
	}
	if floor != want {
		t.Errorf("pow_floor: got %d, want %d (sorted wfs: %v)", floor, want, wfs)
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
	localStore.Put(stamp1, payload1, blockstore.TagPhysical)

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
	localStore.Put(stamp, payload, blockstore.TagPhysical)

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
	remoteStore.Put(stamp1, payload1, blockstore.TagPhysical)
	remoteStore.Put(stamp2, payload2, blockstore.TagPhysical)

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
	localStore.Put(stamp1, payload1, blockstore.TagPhysical)
	localStore.Put(stamp2, payload2, blockstore.TagPhysical)

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
		b.Add(ids[i], 3)
	}
	for _, id := range ids {
		// Must be found at the added level and below.
		for wf := 0; wf <= 3; wf++ {
			if !b.Has(id, wf) {
				t.Errorf("false negative for id %x at wf %d", id, wf)
			}
		}
		// Must not be found above the added level.
		if b.Has(id, 4) {
			t.Errorf("false positive above PoW level for id %x", id)
		}
	}
}

func TestBloomFromBytes(t *testing.T) {
	var b relay.Bloom
	var id blockstore.ID
	id[0] = 0xAB
	b.Add(id, 5)

	data := b.Bytes()
	b2, err := relay.BloomFromBytes(data)
	if err != nil {
		t.Fatalf("BloomFromBytes: %v", err)
	}
	if !b2.Has(id, 5) {
		t.Error("round-tripped bloom lost the inserted id at wf 5")
	}
	if !b2.Has(id, 0) {
		t.Error("round-tripped bloom lost the inserted id at wf 0")
	}

	_, err = relay.BloomFromBytes([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for wrong-size bytes")
	}
}

func TestBloomPowUpgrade(t *testing.T) {
	// A block added at wf=2 should be visible up to level 2 but not level 3.
	// The delta server should include it for a remote that has wf=3.
	var b relay.Bloom
	var id blockstore.ID
	id[0] = 0xCC
	b.Add(id, 2)

	if !b.Has(id, 2) {
		t.Error("expected Has(id, 2) true after Add(id, 2)")
	}
	if b.Has(id, 3) {
		t.Error("expected Has(id, 3) false after Add(id, 2) — remote should send upgrade")
	}
}

// ── webapp endpoint tests ─────────────────────────────────────────────────────

func newRelayServer(t *testing.T, powFloor int) (*httptest.Server, blockstore.Store) {
	t.Helper()
	store := newStore(t)
	srv := relay.NewServer(store, powFloor)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, store
}

func relayGet(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func relayPost(t *testing.T, ts *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func TestWebAppServed(t *testing.T) {
	ts, _ := newRelayServer(t, 0)
	resp := relayGet(t, ts, "/app")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /app: got %d, want 200", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("content-type %q, want text/html", resp.Header.Get("Content-Type"))
	}
}

func TestWebCORS(t *testing.T) {
	ts, _ := newRelayServer(t, 0)
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/blocks", nil)
	req.Header.Set("Origin", "https://example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("expected Access-Control-Allow-Origin: *")
	}
}

func TestWebBlockEndpoints(t *testing.T) {
	ts, store := newRelayServer(t, 0)

	// Seed a block directly into the store.
	stamp, payload := makeBlock(0x42)
	id, err := store.Put(stamp, payload, blockstore.TagPhysical)
	if err != nil {
		t.Fatalf("seed block: %v", err)
	}
	idHex := fmt.Sprintf("%x", id)

	// GET /api/blocks lists it.
	resp := relayGet(t, ts, "/api/blocks")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/blocks: got %d", resp.StatusCode)
	}
	var listResp struct {
		Blocks []struct {
			ID         string `json:"id"`
			Payload    string `json:"payload"`
			Stamp      string `json:"stamp"`
			WorkFactor int    `json:"work_factor"`
		} `json:"blocks"`
	}
	json.NewDecoder(resp.Body).Decode(&listResp)
	if len(listResp.Blocks) != 1 || listResp.Blocks[0].ID != idHex {
		t.Fatalf("unexpected blocks: %+v", listResp.Blocks)
	}

	// GET /api/blocks/{id} fetches the payload and work_factor.
	resp2 := relayGet(t, ts, "/api/blocks/"+idHex)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/blocks/%s: got %d", idHex, resp2.StatusCode)
	}
	var getResp struct {
		WorkFactor int `json:"work_factor"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET block response: %v", err)
	}
	if getResp.WorkFactor != listResp.Blocks[0].WorkFactor {
		t.Errorf("GET block work_factor: got %d, want %d", getResp.WorkFactor, listResp.Blocks[0].WorkFactor)
	}

	// GET /api/blocks/{id} returns 404 for an unknown ID.
	resp3 := relayGet(t, ts, "/api/blocks/"+strings.Repeat("0", 64))
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown block: got %d, want 404", resp3.StatusCode)
	}

	// POST /api/blocks submits the same block again (INSERT OR REPLACE).
	resp4 := relayPost(t, ts, "/api/blocks", map[string]string{
		"stamp":   listResp.Blocks[0].Stamp,
		"payload": listResp.Blocks[0].Payload,
	})
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/blocks: got %d, want 201", resp4.StatusCode)
	}
}

func TestWebSubmitBlockPowFloor(t *testing.T) {
	ts, _ := newRelayServer(t, 99) // unreachably high floor

	// Zero stamp + zero payload has effectively 0 work factor — should be rejected.
	body, _ := json.Marshal(map[string]string{
		"stamp":   "AAAAAA==",                // base64(4 zero bytes)
		"payload": strings.Repeat("A", 2732), // base64(2048 zero bytes) ≈ 2732 chars
	})
	resp, err := http.Post(ts.URL+"/api/blocks", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("expected rejection with pow_floor=99, got 201")
	}
}

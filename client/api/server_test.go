package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
	"github.com/brendanbenshoof/sneakernet/client/api"
)

// testServer wires up a Server backed by in-memory stores.
func testServer(t *testing.T) (*api.Server, string) {
	t.Helper()

	bs, err := blockstore.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	t.Cleanup(func() { bs.Close() })

	ms, err := client.OpenMessageStore(":memory:")
	if err != nil {
		t.Fatalf("open message store: %v", err)
	}
	t.Cleanup(func() { ms.Close() })

	ksPath := filepath.Join(t.TempDir(), "keys.json")
	srv := api.New(bs, ms, ksPath)
	return srv, ksPath
}

func post(t *testing.T, srv http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func get(t *testing.T, srv http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func del(t *testing.T, srv http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func mustJSON(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(v); err != nil {
		t.Fatalf("decode response body: %v (status %d, body: %s)", err, w.Code, w.Body.String())
	}
}

func TestCreateAndUnlock(t *testing.T) {
	srv, _ := testServer(t)

	// Create keystore.
	w := post(t, srv, "/api/keystore/create", map[string]string{"password": "s3cr3t"}, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", w.Code)
	}

	// Unlock returns a token.
	w = post(t, srv, "/api/unlock", map[string]string{"password": "s3cr3t"}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("unlock: got %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustJSON(t, w, &resp)
	if resp["token"] == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	srv, _ := testServer(t)

	post(t, srv, "/api/keystore/create", map[string]string{"password": "correct"}, "")
	w := post(t, srv, "/api/unlock", map[string]string{"password": "wrong"}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestCreateDuplicate(t *testing.T) {
	srv, _ := testServer(t)

	post(t, srv, "/api/keystore/create", map[string]string{"password": "pw"}, "")
	w := post(t, srv, "/api/keystore/create", map[string]string{"password": "pw"}, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	srv, _ := testServer(t)

	for _, path := range []string{"/api/identities", "/api/messages"} {
		w := get(t, srv, path, "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without token: got %d, want 401", path, w.Code)
		}
	}
	for _, path := range []string{"/api/scrape", "/api/send", "/api/lock"} {
		w := post(t, srv, path, nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without token: got %d, want 401", path, w.Code)
		}
	}
}

func unlock(t *testing.T, srv http.Handler) string {
	t.Helper()
	post(t, srv, "/api/keystore/create", map[string]string{"password": "pw"}, "")
	w := post(t, srv, "/api/unlock", map[string]string{"password": "pw"}, "")
	var resp map[string]string
	mustJSON(t, w, &resp)
	return resp["token"]
}

func TestIdentityCRUD(t *testing.T) {
	srv, _ := testServer(t)
	tok := unlock(t, srv)

	// Add identity.
	w := post(t, srv, "/api/identities", map[string]string{"name": "alice"}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("add identity: got %d (body: %s)", w.Code, w.Body.String())
	}
	var addResp map[string]string
	mustJSON(t, w, &addResp)
	if addResp["public_key"] == "" {
		t.Fatal("expected public_key in response")
	}

	// List identities.
	w = get(t, srv, "/api/identities", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("list identities: got %d", w.Code)
	}
	var ids []map[string]string
	mustJSON(t, w, &ids)
	if len(ids) != 1 || ids[0]["name"] != "alice" {
		t.Fatalf("unexpected identities: %v", ids)
	}

	// Duplicate name rejected.
	w = post(t, srv, "/api/identities", map[string]string{"name": "alice"}, tok)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate identity: expected 409, got %d", w.Code)
	}

	// Delete identity.
	w = del(t, srv, "/api/identities/alice", tok)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete identity: got %d", w.Code)
	}

	// Now list should be empty.
	w = get(t, srv, "/api/identities", tok)
	var ids2 []map[string]string
	mustJSON(t, w, &ids2)
	if len(ids2) != 0 {
		t.Fatalf("expected empty list, got %v", ids2)
	}
}

func TestSendAndScrape(t *testing.T) {
	srv, _ := testServer(t)
	tok := unlock(t, srv)

	// Add an identity and grab its public key.
	w := post(t, srv, "/api/identities", map[string]string{"name": "bob"}, tok)
	var addResp map[string]string
	mustJSON(t, w, &addResp)
	pubKey := addResp["public_key"]

	// Send a message to ourselves.
	w = post(t, srv, "/api/send", map[string]string{
		"recipient_public_key": pubKey,
		"message":             "hello from the API",
	}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("send: got %d (body: %s)", w.Code, w.Body.String())
	}
	var sendResp map[string]string
	mustJSON(t, w, &sendResp)
	if sendResp["block_id"] == "" {
		t.Fatal("expected block_id in send response")
	}

	// Scrape should find it.
	w = post(t, srv, "/api/scrape", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("scrape: got %d (body: %s)", w.Code, w.Body.String())
	}
	var scrapeResp map[string]int
	mustJSON(t, w, &scrapeResp)
	if scrapeResp["found"] != 1 {
		t.Fatalf("scrape found %d, want 1", scrapeResp["found"])
	}

	// Message should appear in inbox.
	w = get(t, srv, "/api/messages", tok)
	var msgs []map[string]any
	mustJSON(t, w, &msgs)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
}

func TestLockClearsSession(t *testing.T) {
	srv, _ := testServer(t)
	tok := unlock(t, srv)

	post(t, srv, "/api/lock", nil, tok)

	w := get(t, srv, "/api/identities", tok)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after lock, got %d", w.Code)
	}
}

func TestCORSLocalhost(t *testing.T) {
	srv, _ := testServer(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/unlock", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("CORS header missing or wrong")
	}
}

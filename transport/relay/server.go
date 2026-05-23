// Package relay implements a sneakernet relay-peer transport.
//
// A relay is an internet-hosted node that stores and forwards blocks.
// Peers can push blocks to it, pull blocks they are missing, and query
// its current proof-of-work floor.
//
// Wire format for block bodies (GET and POST /v1/block):
//
//	stamp   [4]byte
//	payload [2048]byte
//	total   2052 bytes, application/octet-stream
package relay

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// Server is an HTTP relay node that accepts and serves blocks.
// It implements http.Handler and can be passed to http.ListenAndServe.
type Server struct {
	store    blockstore.Store
	powFloor int
	mux      *http.ServeMux
}

// NewServer creates a relay Server. powFloor is the minimum work_factor
// accepted on PUT; blocks below this threshold are rejected with 403.
func NewServer(store blockstore.Store, powFloor int) *Server {
	s := &Server{
		store:    store,
		powFloor: powFloor,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/block/{id}", s.handleGet)
	s.mux.HandleFunc("POST /v1/block", s.handlePut)
	s.mux.HandleFunc("POST /v1/delta", s.handleDelta)
	s.mux.HandleFunc("GET /v1/pow-limit", s.handlePowLimit)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// GET /v1/block/{id}  (hex-encoded 32-byte block ID)
// Returns 2052 raw bytes: stamp(4) + payload(2048).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	idBytes, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(idBytes) != blockstore.IDSize {
		http.Error(w, "invalid block id", http.StatusBadRequest)
		return
	}
	var id blockstore.ID
	copy(id[:], idBytes)

	stamp, payload, err := s.store.Get(id)
	if errors.Is(err, blockstore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(stamp[:])
	w.Write(payload[:])
}

// POST /v1/block  body: stamp(4) + payload(2048) raw bytes
// Rejects if work_factor < powFloor. Returns JSON {"id":"<hex>","work_factor":N}.
func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	const blockSize = blockstore.StampSize + blockstore.PayloadSize
	body, err := io.ReadAll(io.LimitReader(r.Body, blockSize+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) != blockSize {
		serverError(w, http.StatusBadRequest, "body must be exactly 2052 bytes (stamp+payload)")
		return
	}

	var stamp blockstore.Stamp
	var payload blockstore.Payload
	copy(stamp[:], body[:blockstore.StampSize])
	copy(payload[:], body[blockstore.StampSize:])

	wf := blockstore.WorkFactor(stamp, payload)
	if wf < s.powFloor {
		serverError(w, http.StatusForbidden, "insufficient proof of work")
		return
	}

	id, err := s.store.Put(stamp, payload)
	if err != nil {
		serverError(w, http.StatusInternalServerError, "storage error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          hex.EncodeToString(id[:]),
		"work_factor": wf,
	})
}

// POST /v1/delta
// Request JSON: {"bloom":"<base64 8192-byte filter>","pow_floor":N,"since":<unix>}
// Response JSON: {"ids":["<hex>",...]}
// Returns IDs of blocks the server has that are not represented in bloom,
// filtered by pow_floor and since (timestamp lower bound).
func (s *Server) handleDelta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Bloom    string `json:"bloom"`
		PowFloor int    `json:"pow_floor"`
		Since    int64  `json:"since"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		serverError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	bloomData, err := base64.StdEncoding.DecodeString(req.Bloom)
	if err != nil {
		serverError(w, http.StatusBadRequest, "invalid bloom encoding")
		return
	}
	bloom, err := BloomFromBytes(bloomData)
	if err != nil {
		serverError(w, http.StatusBadRequest, err.Error())
		return
	}

	powFloor := req.PowFloor
	if powFloor < s.powFloor {
		powFloor = s.powFloor
	}
	since := time.Unix(req.Since, 0)

	ids := []string{} // non-nil so JSON encodes as []
	pageToken := ""
	for {
		next, refs, err := s.store.ListBlocks(pageToken, 500, powFloor, since)
		if err != nil {
			serverError(w, http.StatusInternalServerError, "store error")
			return
		}
		for _, ref := range refs {
			if !bloom.Has(ref.ID) {
				ids = append(ids, hex.EncodeToString(ref.ID[:]))
			}
		}
		if next == "" {
			break
		}
		pageToken = next
	}

	writeJSON(w, http.StatusOK, map[string]any{"ids": ids})
}

// GET /v1/pow-limit
// Returns JSON {"pow_floor":N} — the minimum work_factor this relay accepts.
func (s *Server) handlePowLimit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"pow_floor": s.powFloor})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func serverError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

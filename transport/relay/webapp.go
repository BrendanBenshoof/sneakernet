package relay

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

//go:embed ui/app.html
var appHTML []byte

//go:embed ui/index.html
var indexHTML []byte

// GET / — relay landing page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// GET /app — public webapp served from the relay port.
func (s *Server) handleWebApp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(appHTML)
}

// GET /api/blocks?since=<unix>&page_token=<str>&pow_floor=<int>&limit=<int>
// Returns a paginated list of blocks with full payloads (base64).
func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	sinceUnix, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	since := time.Unix(sinceUnix, 0)

	powFloor, _ := strconv.Atoi(q.Get("pow_floor"))
	if powFloor < s.powFloor {
		powFloor = s.powFloor
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}

	nextToken, refs, err := s.store.ListBlocks(q.Get("page_token"), limit, powFloor, since)
	if err != nil {
		serverError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type blockItem struct {
		ID         string `json:"id"`
		WorkFactor int    `json:"work_factor"`
		CreatedAt  int64  `json:"created_at"`
		Stamp      string `json:"stamp"`
		Payload    string `json:"payload"`
	}

	items := make([]blockItem, 0, len(refs))
	var resumeToken string
	for _, ref := range refs {
		stamp, payload, err := s.store.Get(ref.ID)
		if err != nil {
			continue
		}
		items = append(items, blockItem{
			ID:         hex.EncodeToString(ref.ID[:]),
			WorkFactor: ref.WorkFactor,
			CreatedAt:  ref.CreatedAt,
			Stamp:      base64.StdEncoding.EncodeToString(stamp[:]),
			Payload:    base64.StdEncoding.EncodeToString(payload[:]),
		})
		resumeToken = ref.Token()
	}

	type listResp struct {
		Blocks        []blockItem `json:"blocks"`
		NextPageToken string      `json:"next_page_token,omitempty"`
		ResumeToken   string      `json:"resume_token,omitempty"`
	}
	writeJSON(w, http.StatusOK, listResp{Blocks: items, NextPageToken: nextToken, ResumeToken: resumeToken})
}

// GET /api/blocks/{id} — fetch a single block by hex-encoded ID.
func (s *Server) handleGetBlock(w http.ResponseWriter, r *http.Request) {
	idBytes, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(idBytes) != blockstore.IDSize {
		serverError(w, http.StatusBadRequest, "invalid block id")
		return
	}
	var id blockstore.ID
	copy(id[:], idBytes)

	stamp, payload, err := s.store.Get(id)
	if errors.Is(err, blockstore.ErrNotFound) {
		serverError(w, http.StatusNotFound, "block not found")
		return
	}
	if err != nil {
		serverError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      hex.EncodeToString(id[:]),
		"stamp":   base64.StdEncoding.EncodeToString(stamp[:]),
		"payload": base64.StdEncoding.EncodeToString(payload[:]),
	})
}

// POST /api/blocks  {"stamp":"<base64>","payload":"<base64>"}
// Submits a pre-encrypted block. Enforces the relay's pow_floor.
func (s *Server) handleSubmitBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Stamp   string `json:"stamp"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		serverError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	stampBytes, err := base64.StdEncoding.DecodeString(req.Stamp)
	if err != nil || len(stampBytes) != blockstore.StampSize {
		serverError(w, http.StatusBadRequest, "invalid stamp: must be base64-encoded 4 bytes")
		return
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil || len(payloadBytes) != blockstore.PayloadSize {
		serverError(w, http.StatusBadRequest, "invalid payload: must be base64-encoded 2048 bytes")
		return
	}

	var stamp blockstore.Stamp
	var payload blockstore.Payload
	copy(stamp[:], stampBytes)
	copy(payload[:], payloadBytes)

	if wf := blockstore.WorkFactor(stamp, payload); wf < s.powFloor {
		serverError(w, http.StatusForbidden, "insufficient proof of work")
		return
	}

	id, err := s.store.Put(stamp, payload, blockstore.TagPhysical)
	if err != nil {
		serverError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          hex.EncodeToString(id[:]),
		"work_factor": blockstore.WorkFactor(stamp, payload),
	})
}

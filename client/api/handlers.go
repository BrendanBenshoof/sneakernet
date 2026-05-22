package api

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
)

// POST /api/keystore/create  {"password":"..."}
// Creates a new keystore file. Returns 409 if one already exists.
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password required")
		return
	}
	if _, err := os.Stat(s.ksPath); err == nil {
		writeError(w, http.StatusConflict, "keystore already exists; use /api/unlock")
		return
	}
	ks, err := client.NewKeystore([]byte(req.Password))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create keystore")
		return
	}
	if err := ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// POST /api/unlock  {"password":"..."}
// Derives the master key, loads all identities, and returns a session token.
// Returns 404 if no keystore file exists, 401 on wrong password.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}

	// LoadKeystore runs Argon2id — call without holding the lock.
	ks, err := client.LoadKeystore(s.ksPath, []byte(req.Password))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "keystore not found; call /api/keystore/create first")
		} else {
			writeError(w, http.StatusUnauthorized, "invalid password or corrupted keystore")
		}
		return
	}

	token, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	s.mu.Lock()
	s.ks = ks
	s.tokens[token] = struct{}{}
	s.rebuildScraper()
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// POST /api/lock
// Clears all session tokens and wipes keys from memory.
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.ks = nil
	s.scraper = nil
	s.tokens = make(map[string]struct{})
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/identities
// Returns all stored identities with their public keys (base64).
func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ids := s.ks.List()
	s.mu.RUnlock()

	type identityResp struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	out := make([]identityResp, len(ids))
	for i, id := range ids {
		out[i] = identityResp{
			Name:      id.Name,
			PublicKey: base64.StdEncoding.EncodeToString(id.Key.PublicKey().Bytes()),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/identities  {"name":"alice"}
// Generates a new X25519 identity, saves the keystore, and returns the public key.
func (s *Server) handleAddIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.ks.Add(req.Name)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	pub := base64.StdEncoding.EncodeToString(id.Key.PublicKey().Bytes())
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	writeJSON(w, http.StatusCreated, map[string]string{"name": req.Name, "public_key": pub})
}

// DELETE /api/identities/{name}
// Removes the named identity, saves the keystore.
func (s *Server) handleRemoveIdentity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ks.Remove(name) {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	s.rebuildScraper()

	w.WriteHeader(http.StatusNoContent)
}

// GET /api/messages?after_id=N
// Returns messages with id > after_id (default 0). Use for simple poll-based sync.
// Message content is base64-encoded; block_id is hex.
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	afterID, _ := strconv.ParseInt(r.URL.Query().Get("after_id"), 10, 64)

	msgs, err := s.msgs.ListMessagesAfter(afterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list messages")
		return
	}

	type msgResp struct {
		ID         int64  `json:"id"`
		BlockID    string `json:"block_id"`
		Content    string `json:"content"`
		ReceivedAt string `json:"received_at"`
	}
	out := make([]msgResp, len(msgs))
	for i, m := range msgs {
		out[i] = msgResp{
			ID:         m.ID,
			BlockID:    hex.EncodeToString(m.BlockID[:]),
			Content:    base64.StdEncoding.EncodeToString(m.Content),
			ReceivedAt: m.ReceivedAt.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/scrape
// Scans all new blocks and attempts decryption with every stored identity.
// Returns {"found": N} where N is newly decoded messages this run.
// Concurrent scrape calls are serialised; the request blocks until done.
func (s *Server) handleScrape(w http.ResponseWriter, r *http.Request) {
	s.scrapeMu.Lock()
	defer s.scrapeMu.Unlock()

	s.mu.RLock()
	scraper := s.scraper
	s.mu.RUnlock()

	found, err := scraper.Scrape(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scrape failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"found": found})
}

// POST /api/send  {"recipient_public_key":"<base64>","message":"<text>"}
// Encrypts message for the recipient and stores the resulting block.
// Returns {"block_id":"<hex>"}.
// The block is stored with a zero stamp (work_factor 0, TTL 24 h). Stamp
// mining for longer TTLs is not yet implemented.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RecipientPublicKey string `json:"recipient_public_key"`
		Message            string `json:"message"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.RecipientPublicKey == "" || req.Message == "" {
		writeError(w, http.StatusBadRequest, "recipient_public_key and message required")
		return
	}

	pubBytes, err := base64.StdEncoding.DecodeString(req.RecipientPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid recipient_public_key encoding")
		return
	}
	recipientPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid recipient public key")
		return
	}

	payload, err := client.Encrypt(recipientPub, []byte(req.Message))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var stamp blockstore.Stamp
	id, err := s.blocks.Put(stamp, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store block")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"block_id": hex.EncodeToString(id[:])})
}

// POST /api/keystore/change-password  {"new_password":"..."}
// Re-keys the keystore with a new password and saves it. All existing tokens
// remain valid; the old password can no longer unlock the file.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "new_password required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ks.ChangePassword([]byte(req.NewPassword)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to change password")
		return
	}
	if err := s.ks.Save(s.ksPath); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save keystore")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

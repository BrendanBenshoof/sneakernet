package api

import (
	"encoding/base64"
	"net/http"
)

// GET /api/peers — returns all tracked peers; no auth required.
func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	var peers []PeerInfo
	if s.peers != nil {
		peers = s.peers.ListPeers()
	}
	if peers == nil {
		peers = []PeerInfo{}
	}
	writeJSON(w, http.StatusOK, map[string][]PeerInfo{"peers": peers})
}

// POST /api/peers  {"url":"https://relay.example.com"}
func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	if s.peers == nil {
		writeError(w, http.StatusServiceUnavailable, "peer management not available")
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "url required")
		return
	}
	if !s.peers.AddPeer(req.URL, "manual") {
		writeError(w, http.StatusConflict, "peer already known or limit reached")
		return
	}
	s.peers.Save()
	writeJSON(w, http.StatusCreated, map[string]string{"url": req.URL})
}

// DELETE /api/peers/{b64url}  (b64url = base64url-encoded peer URL, no padding)
func (s *Server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	if s.peers == nil {
		writeError(w, http.StatusServiceUnavailable, "peer management not available")
		return
	}
	peerURL, ok := decodePeerURL(w, r)
	if !ok {
		return
	}
	s.peers.RemovePeer(peerURL)
	s.peers.Save()
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/peers/{b64url}/block
func (s *Server) handleBlockPeer(w http.ResponseWriter, r *http.Request) {
	if s.peers == nil {
		writeError(w, http.StatusServiceUnavailable, "peer management not available")
		return
	}
	peerURL, ok := decodePeerURL(w, r)
	if !ok {
		return
	}
	s.peers.BlockPeer(peerURL)
	s.peers.Save()
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/peers/{b64url}/unblock
func (s *Server) handleUnblockPeer(w http.ResponseWriter, r *http.Request) {
	if s.peers == nil {
		writeError(w, http.StatusServiceUnavailable, "peer management not available")
		return
	}
	peerURL, ok := decodePeerURL(w, r)
	if !ok {
		return
	}
	s.peers.UnblockPeer(peerURL)
	s.peers.Save()
	w.WriteHeader(http.StatusNoContent)
}

func decodePeerURL(w http.ResponseWriter, r *http.Request) (string, bool) {
	b, err := base64.RawURLEncoding.DecodeString(r.PathValue("b64url"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid peer url encoding")
		return "", false
	}
	return string(b), true
}

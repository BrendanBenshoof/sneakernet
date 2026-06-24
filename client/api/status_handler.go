package api

import "net/http"

// GET /api/status — returns live node metrics and the full peer list.
// No authentication required so the UI can always render connection state.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	btSessions := 0
	if s.status != nil {
		btSessions = s.status.ActiveBTSessions()
	}
	peers := []PeerInfo{}
	if s.peers != nil {
		peers = s.peers.ListPeers()
	}

	resp := map[string]any{
		"active_bt_sessions": btSessions,
		"peers":              peers,
	}

	type diskUsager interface{ DiskUsageBytes() int64 }
	if du, ok := s.blocks.(diskUsager); ok {
		resp["disk_usage_bytes"] = du.DiskUsageBytes()
	}

	writeJSON(w, http.StatusOK, resp)
}

// POST /api/sync — triggers an immediate sync round outside the normal interval.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeError(w, http.StatusServiceUnavailable, "sync not available")
		return
	}
	s.status.SyncNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sync started"})
}

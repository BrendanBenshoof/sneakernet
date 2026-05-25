// Package api provides an HTTP API server over the sneakernet client.
//
// The server handles two primary use cases: a locally-hosted web UI and
// mobile app clients. All state-mutating routes require a Bearer token
// obtained by posting the keystore password to /api/unlock.
//
// # Authentication flow
//
//  1. On first run, POST /api/keystore/create with a password to initialise
//     the keystore file.
//  2. POST /api/unlock with the password to receive a session token.
//  3. Include "Authorization: Bearer <token>" on every subsequent request.
//  4. POST /api/lock to clear the session and wipe keys from memory.
//
// # CORS
//
// Requests from localhost, 127.0.0.1, and common mobile hybrid-app origins
// (capacitor://, ionic://) are granted permissive CORS headers so that a
// browser-based or Capacitor-wrapped UI can call the API without a proxy.
package api

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
)

//go:embed ui/index.html
var indexHTML []byte

// Server is an HTTP API server wrapping the sneakernet client stack.
// It implements http.Handler and can be passed directly to http.ListenAndServe.
type Server struct {
	blocks blockstore.Store
	msgs   *client.MessageStore
	ksPath string

	mu       sync.RWMutex
	ks       *client.Keystore // nil when locked
	scraper  *client.Client   // nil when locked
	tokens   map[string]struct{}

	scrapeMu sync.Mutex // one scrape at a time
	mux      *http.ServeMux
}

// New creates an API server. blocks and msgs must already be open;
// keystorePath is the path to the (possibly not-yet-created) keystore file.
func New(blocks blockstore.Store, msgs *client.MessageStore, keystorePath string) *Server {
	s := &Server{
		blocks: blocks,
		msgs:   msgs,
		ksPath: keystorePath,
		tokens: make(map[string]struct{}),
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); isLocalOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	s.mux.HandleFunc("POST /api/keystore/create", s.handleCreate)
	s.mux.HandleFunc("POST /api/keystore/change-password", s.auth(s.handleChangePassword))
	s.mux.HandleFunc("POST /api/unlock", s.handleUnlock)
	s.mux.HandleFunc("POST /api/lock", s.auth(s.handleLock))
	s.mux.HandleFunc("GET /api/identities", s.auth(s.handleListIdentities))
	s.mux.HandleFunc("POST /api/identities", s.auth(s.handleAddIdentity))
	s.mux.HandleFunc("DELETE /api/identities/{name}", s.auth(s.handleRemoveIdentity))
	s.mux.HandleFunc("GET /api/channels", s.auth(s.handleListChannels))
	s.mux.HandleFunc("POST /api/channels", s.auth(s.handleAddChannel))
	s.mux.HandleFunc("DELETE /api/channels/{name}", s.auth(s.handleRemoveChannel))
	s.mux.HandleFunc("GET /api/messages", s.auth(s.handleListMessages))
	s.mux.HandleFunc("GET /api/messages/{block_id}", s.auth(s.handleGetMessage))
	s.mux.HandleFunc("POST /api/scrape", s.auth(s.handleScrape))
	s.mux.HandleFunc("POST /api/send", s.auth(s.handleSend))
	s.mux.HandleFunc("POST /api/send-channel", s.auth(s.handleSendChannel))
	s.mux.HandleFunc("GET /api/contacts", s.auth(s.handleListContacts))
	s.mux.HandleFunc("POST /api/contacts", s.auth(s.handleAddContact))
	s.mux.HandleFunc("DELETE /api/contacts/{pub_key}", s.auth(s.handleRemoveContact))
	s.mux.HandleFunc("PATCH /api/contacts/{pub_key}", s.auth(s.handleRenameContact))
}

// auth wraps a handler requiring a valid Bearer token.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.RLock()
		_, ok := s.tokens[token]
		s.mu.RUnlock()
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, "invalid or missing token")
			return
		}
		next(w, r)
	}
}

// rebuildScraper recreates the Client from the current keystore identities and channels.
// Caller must hold s.mu write lock.
func (s *Server) rebuildScraper() {
	s.scraper = client.New(s.blocks, s.msgs, s.ks.Keys(), s.ks.Channels())
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func isLocalOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://localhost") ||
		strings.HasPrefix(origin, "http://127.0.0.1") ||
		strings.HasPrefix(origin, "capacitor://") || // Capacitor (iOS/Android)
		strings.HasPrefix(origin, "ionic://")        // Ionic
}

package mobile

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/brendanbenshoof/sneakernet/client/api"
)

const maxTrackedPeers = 200

type peerEntry struct {
	URL        string    `json:"url"`
	Source     string    `json:"source"` // "manual", "lan", "bluetooth", "gossip"
	Blocked    bool      `json:"blocked"`
	AddedAt    time.Time `json:"added_at"`
	LastSync   time.Time `json:"last_sync,omitempty"`
	Failures   int       `json:"failures,omitempty"`
	LastPulled int       `json:"last_pulled,omitempty"`
	LastPushed int       `json:"last_pushed,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

type peerTracker struct {
	mu    sync.Mutex
	peers map[string]*peerEntry
	path  string
}

func newPeerTracker(path string) *peerTracker {
	return &peerTracker{
		peers: make(map[string]*peerEntry, 32),
		path:  path,
	}
}

func (pt *peerTracker) load() {
	data, err := os.ReadFile(pt.path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		return
	}
	var v struct {
		Peers []peerEntry `json:"peers"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	for i := range v.Peers {
		e := v.Peers[i]
		pt.peers[e.URL] = &e
	}
}

func (pt *peerTracker) save() {
	pt.mu.Lock()
	entries := make([]peerEntry, 0, len(pt.peers))
	for _, e := range pt.peers {
		entries = append(entries, *e)
	}
	pt.mu.Unlock()

	data, err := json.Marshal(map[string]any{"peers": entries})
	if err != nil {
		return
	}
	tmp := pt.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	os.Rename(tmp, pt.path) //nolint:errcheck
}

// add inserts a peer if not already present and under capacity.
// Returns true if the peer was newly added.
func (pt *peerTracker) add(rawURL, source string) bool {
	rawURL = normalizeURL(rawURL)
	if rawURL == "" {
		return false
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if _, exists := pt.peers[rawURL]; exists {
		return false
	}
	if len(pt.peers) >= maxTrackedPeers {
		return false
	}
	pt.peers[rawURL] = &peerEntry{
		URL:     rawURL,
		Source:  source,
		AddedAt: time.Now(),
	}
	return true
}

func (pt *peerTracker) remove(rawURL string) {
	rawURL = normalizeURL(rawURL)
	if rawURL == "" {
		return
	}
	pt.mu.Lock()
	delete(pt.peers, rawURL)
	pt.mu.Unlock()
}

// block marks a peer as blocked; adds it if not yet tracked.
func (pt *peerTracker) block(rawURL string) {
	rawURL = normalizeURL(rawURL)
	if rawURL == "" {
		return
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if e, ok := pt.peers[rawURL]; ok {
		e.Blocked = true
	} else {
		pt.peers[rawURL] = &peerEntry{URL: rawURL, Source: "manual", Blocked: true, AddedAt: time.Now()}
	}
}

func (pt *peerTracker) unblock(rawURL string) {
	rawURL = normalizeURL(rawURL)
	if rawURL == "" {
		return
	}
	pt.mu.Lock()
	if e, ok := pt.peers[rawURL]; ok {
		e.Blocked = false
	}
	pt.mu.Unlock()
}

// activeURLs returns all non-blocked peer URLs.
func (pt *peerTracker) activeURLs() []string {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	out := make([]string, 0, len(pt.peers))
	for u, e := range pt.peers {
		if !e.Blocked {
			out = append(out, u)
		}
	}
	return out
}

// pickPeer returns the non-blocked peer with the oldest LastSync time
// (zero time = never synced, sorts first). Returns "" if none available.
func (pt *peerTracker) pickPeer() string {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	var pick string
	var pickTime time.Time
	first := true
	for u, e := range pt.peers {
		if e.Blocked {
			continue
		}
		if first || e.LastSync.Before(pickTime) {
			pick = u
			pickTime = e.LastSync
			first = false
		}
	}
	return pick
}

func (pt *peerTracker) lastSync(rawURL string) time.Time {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if e, ok := pt.peers[rawURL]; ok {
		return e.LastSync
	}
	return time.Time{}
}

func (pt *peerTracker) recordSuccess(rawURL string, pulled, pushed int, syncErr string) {
	pt.mu.Lock()
	if e, ok := pt.peers[rawURL]; ok {
		e.Failures = 0
		e.LastSync = time.Now()
		e.LastPulled = pulled
		e.LastPushed = pushed
		e.LastError = syncErr
	}
	pt.mu.Unlock()
}

func (pt *peerTracker) recordFailure(rawURL string, pullErr string) {
	pt.mu.Lock()
	if e, ok := pt.peers[rawURL]; ok {
		e.Failures++
		e.LastError = pullErr
	}
	pt.mu.Unlock()
}

// --- api.PeerManager implementation ---

func (pt *peerTracker) Save() { pt.save() }

func (pt *peerTracker) AddPeer(rawURL, source string) bool {
	return pt.add(rawURL, source)
}

func (pt *peerTracker) RemovePeer(rawURL string) {
	pt.remove(rawURL)
}

func (pt *peerTracker) BlockPeer(rawURL string) {
	pt.block(rawURL)
}

func (pt *peerTracker) UnblockPeer(rawURL string) {
	pt.unblock(rawURL)
}

func (pt *peerTracker) ListPeers() []api.PeerInfo {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	out := make([]api.PeerInfo, 0, len(pt.peers))
	for _, e := range pt.peers {
		info := api.PeerInfo{
			URL:        e.URL,
			Source:     e.Source,
			Blocked:    e.Blocked,
			AddedAt:    e.AddedAt,
			Failures:   e.Failures,
			LastPulled: e.LastPulled,
			LastPushed: e.LastPushed,
			LastError:  e.LastError,
		}
		if !e.LastSync.IsZero() {
			t := e.LastSync
			info.LastSync = &t
		}
		out = append(out, info)
	}
	return out
}

// normalizeURL strips trailing slashes and validates that the URL has an
// http/https scheme and a non-empty host. Returns "" on invalid input.
func normalizeURL(rawURL string) string {
	rawURL = strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return rawURL
}

// Package dht discovers sneakernet relay peers via BitTorrent mainline DHT (BEP 5).
//
// The DHT rendezvous key rotates each UTC hour: it is the SHA-1 of a fixed
// prefix concatenated with the current Unix epoch divided by 3600. To tolerate
// clock skew, nodes poll the previous, current, and next hour's info-hashes,
// but only announce (announce_peer) to the current hour's hash.
//
// No modifications to the DHT network are made; this is a standard use of
// BEP 5 announce_peer with implied_port=0 and an application-specific port.
package dht

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// dhtPrefix is the versioned string prefix for the rotating DHT info-hash.
// Changing this prefix breaks compatibility with all existing nodes.
const dhtPrefix = "sneakernet-relay-v2"

// infoHashForHour returns the DHT info-hash for the given Unix hour index
// (Unix epoch divided by 3600).
func infoHashForHour(hour int64) [20]byte {
	return sha1.Sum([]byte(fmt.Sprintf("%s-%d", dhtPrefix, hour)))
}

// currentInfoHash returns the info-hash for the current UTC hour.
func currentInfoHash() [20]byte {
	return infoHashForHour(time.Now().Unix() / 3600)
}

// dhtInfoHashes returns info-hashes for the previous, current, and next UTC
// hours. Polling all three tolerates clock skew between peers.
func dhtInfoHashes() [3][20]byte {
	h := time.Now().Unix() / 3600
	return [3][20]byte{
		infoHashForHour(h - 1),
		infoHashForHour(h),
		infoHashForHour(h + 1),
	}
}

var bootstrapAddrs = []string{
	"router.bittorrent.com:6881",
	"router.utorrent.com:6881",
	"dht.transmissionbt.com:6881",
}

const (
	maxNodes         = 256
	getPeersInterval = 5 * time.Minute
	announceInterval = 15 * time.Minute // DHT nodes expire entries after ~30 min
	responseTimeout  = 10 * time.Second
	maxUDPMsg        = 2048
)

type nodeEntry struct {
	addr  *net.UDPAddr
	token []byte    // token received via get_peers; required for announce_peer
	seen  time.Time
}

type pendingReq struct {
	deadline time.Time
	handler  func(map[string]any)
}

// Discovery performs sneakernet peer discovery via mainline DHT.
// Call Start to begin; read discovered relay addresses from Peers.
type Discovery struct {
	nodeID [20]byte
	port   int // sneakernet relay HTTP port to advertise
	conn   *net.UDPConn
	peers  chan string // emits "host:port" strings for discovered relays

	mu      sync.Mutex
	nodes   map[string]*nodeEntry // UDP addr string → node
	pending map[string]pendingReq // transaction ID → in-flight request
}

// New creates a Discovery that will announce the given relay HTTP port.
// Call Start to join the DHT network.
func New(relayPort int) (*Discovery, error) {
	var id [20]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("dht: generate node id: %w", err)
	}
	return &Discovery{
		nodeID:  id,
		port:    relayPort,
		peers:   make(chan string, 64),
		nodes:   make(map[string]*nodeEntry),
		pending: make(map[string]pendingReq),
	}, nil
}

// Peers returns the channel of discovered relay addresses ("host:port").
// The channel is buffered; drain it continuously to avoid blocking discovery.
func (d *Discovery) Peers() <-chan string { return d.peers }

// InfoHash returns the current hour's DHT info-hash used as the sneakernet rendezvous key.
func (d *Discovery) InfoHash() [20]byte { return currentInfoHash() }

// Start opens a UDP socket, bootstraps into the mainline DHT, and continuously
// discovers and announces peers. It blocks until ctx is cancelled.
func (d *Discovery) Start(ctx context.Context) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("dht: listen: %w", err)
	}
	d.conn = conn

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go d.receiveLoop()

	// Seed the node table from well-known bootstrap addresses.
	for _, addr := range bootstrapAddrs {
		ua, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			continue
		}
		d.mu.Lock()
		d.nodes[ua.String()] = &nodeEntry{addr: ua, seen: time.Now()}
		d.mu.Unlock()
		for _, h := range dhtInfoHashes() {
			d.sendGetPeers(ua, h)
		}
	}

	getPeersTick := time.NewTicker(getPeersInterval)
	announceTick := time.NewTicker(announceInterval)
	cleanupTick  := time.NewTicker(time.Minute)
	defer getPeersTick.Stop()
	defer announceTick.Stop()
	defer cleanupTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-getPeersTick.C:
			d.broadcastGetPeers()
		case <-announceTick.C:
			d.announceAll()
		case <-cleanupTick.C:
			d.cleanupPending()
		}
	}
}

// receiveLoop reads UDP packets and dispatches DHT messages until the
// connection is closed (via ctx cancellation in Start).
func (d *Discovery) receiveLoop() {
	buf := make([]byte, maxUDPMsg)
	for {
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw, _, err := decode(buf[:n])
		if err != nil {
			continue
		}
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		d.dispatch(msg, from)
	}
}

func (d *Discovery) dispatch(msg map[string]any, from *net.UDPAddr) {
	switch msg["y"] {
	case "r": // response to one of our outgoing queries
		txid, _ := msg["t"].(string)
		d.mu.Lock()
		req, ok := d.pending[txid]
		if ok {
			delete(d.pending, txid)
		}
		d.mu.Unlock()
		if ok {
			if r, ok := msg["r"].(map[string]any); ok {
				req.handler(r)
			}
		}

	case "q": // incoming query from another DHT node
		method, _ := msg["q"].(string)
		txid, _ := msg["t"].(string)
		switch method {
		case "ping":
			d.sendPong(txid, from)
		case "find_node":
			d.sendPong(txid, from) // minimal response; enough to stay "good"
		}
		// Mark the node as recently seen.
		d.mu.Lock()
		if n, ok := d.nodes[from.String()]; ok {
			n.seen = time.Now()
		}
		d.mu.Unlock()
	}
}

// sendGetPeers sends a get_peers query for the given info-hash to addr.
func (d *Discovery) sendGetPeers(addr *net.UDPAddr, infoHash [20]byte) {
	txid := d.newTxID()
	d.mu.Lock()
	d.pending[txid] = pendingReq{
		deadline: time.Now().Add(responseTimeout),
		handler:  func(r map[string]any) { d.handleGetPeersResp(addr, r) },
	}
	d.mu.Unlock()
	d.send(addr, map[string]any{
		"t": txid,
		"y": "q",
		"q": "get_peers",
		"a": map[string]any{
			"id":        string(d.nodeID[:]),
			"info_hash": string(infoHash[:]),
		},
	})
}

// handleGetPeersResp processes the response to a get_peers query.
// It records the token (for subsequent announce_peer), emits discovered
// sneakernet peers, and expands the node table from compact node info.
func (d *Discovery) handleGetPeersResp(from *net.UDPAddr, r map[string]any) {
	// Record the token so we can announce_peer to this node.
	token, hasToken := r["token"].(string)
	d.mu.Lock()
	if _, exists := d.nodes[from.String()]; !exists && len(d.nodes) < maxNodes {
		d.nodes[from.String()] = &nodeEntry{addr: from}
	}
	if n, ok := d.nodes[from.String()]; ok {
		n.seen = time.Now()
		if hasToken {
			n.token = []byte(token)
		}
	}
	d.mu.Unlock()

	// Announce immediately once we have a token from this node.
	if hasToken {
		d.sendAnnounce(from, []byte(token))
	}

	// "values": list of 6-byte compact peer records — these are sneakernet relays.
	if values, ok := r["values"].([]any); ok {
		for _, v := range values {
			raw, _ := v.(string)
			if addr := parseCompactPeer([]byte(raw)); addr != "" {
				select {
				case d.peers <- addr:
				default: // drop if consumer is slow; they'll appear again
				}
			}
		}
	}

	// "nodes": string of 26-byte compact node records — expand our routing table.
	if nodesRaw, ok := r["nodes"].(string); ok {
		newAddrs := d.addCompactNodes([]byte(nodesRaw))
		for _, ua := range newAddrs {
			for _, h := range dhtInfoHashes() {
				d.sendGetPeers(ua, h)
			}
		}
	}
}

// sendAnnounce sends an announce_peer for the current hour's info-hash with our relay port.
// We always announce to the current hour only; peers poll prev/current/next to find us.
func (d *Discovery) sendAnnounce(addr *net.UDPAddr, token []byte) {
	h := currentInfoHash()
	d.send(addr, map[string]any{
		"t": d.newTxID(),
		"y": "q",
		"q": "announce_peer",
		"a": map[string]any{
			"id":           string(d.nodeID[:]),
			"implied_port": 0,
			"info_hash":    string(h[:]),
			"port":         d.port,
			"token":        string(token),
		},
	})
}

func (d *Discovery) sendPong(txid string, to *net.UDPAddr) {
	d.send(to, map[string]any{
		"t": txid,
		"y": "r",
		"r": map[string]any{"id": string(d.nodeID[:])},
	})
}

// broadcastGetPeers sends get_peers to every known node for the previous,
// current, and next hour's info-hashes.
func (d *Discovery) broadcastGetPeers() {
	hashes := dhtInfoHashes()
	d.mu.Lock()
	addrs := make([]*net.UDPAddr, 0, len(d.nodes))
	for _, n := range d.nodes {
		addrs = append(addrs, n.addr)
	}
	d.mu.Unlock()
	for _, addr := range addrs {
		for _, h := range hashes {
			d.sendGetPeers(addr, h)
		}
	}
}

// announceAll re-announces to every node for which we hold a token.
// DHT nodes expire peer entries after ~30 minutes, so we do this every 15.
func (d *Discovery) announceAll() {
	type target struct {
		addr  *net.UDPAddr
		token []byte
	}
	d.mu.Lock()
	var targets []target
	for _, n := range d.nodes {
		if len(n.token) > 0 {
			targets = append(targets, target{n.addr, n.token})
		}
	}
	d.mu.Unlock()
	for _, t := range targets {
		d.sendAnnounce(t.addr, t.token)
	}
}

// addCompactNodes parses a string of 26-byte compact node records, adds any
// previously-unknown ones to the node table, and returns their addresses.
func (d *Discovery) addCompactNodes(data []byte) []*net.UDPAddr {
	var newAddrs []*net.UDPAddr
	parsed := parseCompactNodes(data)
	d.mu.Lock()
	for _, ua := range parsed {
		key := ua.String()
		if _, exists := d.nodes[key]; !exists && len(d.nodes) < maxNodes {
			d.nodes[key] = &nodeEntry{addr: ua, seen: time.Now()}
			newAddrs = append(newAddrs, ua)
		}
	}
	d.mu.Unlock()
	return newAddrs
}

// cleanupPending removes timed-out in-flight requests.
func (d *Discovery) cleanupPending() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for txid, req := range d.pending {
		if now.After(req.deadline) {
			delete(d.pending, txid)
		}
	}
}

func (d *Discovery) send(addr *net.UDPAddr, msg map[string]any) {
	d.conn.WriteToUDP(encode(msg), addr)
}

func (d *Discovery) newTxID() string {
	var b [2]byte
	rand.Read(b[:])
	return string(b[:])
}

// parseCompactPeer parses a 6-byte BEP 5 compact peer record into "host:port".
// Returns "" for malformed input.
func parseCompactPeer(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	ip := net.IP(b[:4])
	port := binary.BigEndian.Uint16(b[4:6])
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// parseCompactNodes parses a byte slice of 26-byte compact node records
// (20-byte node ID + 6-byte compact peer) into UDP addresses.
func parseCompactNodes(b []byte) []*net.UDPAddr {
	var out []*net.UDPAddr
	for len(b) >= 26 {
		ip := make(net.IP, 4)
		copy(ip, b[20:24])
		port := int(binary.BigEndian.Uint16(b[24:26]))
		if port > 0 {
			out = append(out, &net.UDPAddr{IP: ip, Port: port})
		}
		b = b[26:]
	}
	return out
}

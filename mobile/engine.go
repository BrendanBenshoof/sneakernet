// Package mobile provides a gomobile-compatible API for the sneakernet engine.
//
// Build the Android AAR with:
//
//	gomobile bind -target android -javapkg com.sneakernet.engine -o android/app/libs/mobile.aar ./mobile/
package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
	"github.com/brendanbenshoof/sneakernet/client/api"
	"github.com/brendanbenshoof/sneakernet/transport/bluetooth"
	"github.com/brendanbenshoof/sneakernet/transport/lan"
	"github.com/brendanbenshoof/sneakernet/transport/relay"
)

// quotaFileName is a sibling of the blockstore directory. Its size is kept at
// (storageLimit - db.Size()), so the app's total visible footprint in the OS
// storage viewer always reflects the user's configured budget rather than
// growing gradually as content accumulates.
const (
	quotaFileName     = ".storage_quota"
	quotaSyncInterval = 10 * time.Second
)

// Engine is the sneakernet mobile engine. Create one per app process via
// NewEngine and hold it for the lifetime of the Application object.
type Engine struct {
	store     *blockstore.BadgerStore // concrete type so we can call WithStorageLimit
	msgs      *client.MessageStore
	pm        *peerTracker
	dataDir   string
	quotaPath string

	ctx    context.Context
	cancel context.CancelFunc

	quotaOnce sync.Once // ensures quota sync goroutine starts at most once
	syncOnce  sync.Once // ensures peer sync loop starts at most once
	lanOnce   sync.Once // ensures LAN discovery loop starts at most once

	activeBTCount int32 // atomic; number of in-progress Bluetooth sessions
}

// NewEngine opens (or creates) a sneakernet node in dataDir.
// Pass context.getFilesDir().getAbsolutePath() from Android.
func NewEngine(dataDir string) (*Engine, error) {
	bs, err := blockstore.OpenBadger(filepath.Join(dataDir, "blocks.db"))
	if err != nil {
		return nil, fmt.Errorf("mobile: open blockstore: %w", err)
	}
	ms, err := client.OpenMessageStore(filepath.Join(dataDir, "messages.db"))
	if err != nil {
		bs.Close()
		return nil, fmt.Errorf("mobile: open message store: %w", err)
	}
	pm := newPeerTracker(filepath.Join(dataDir, "peers.json"))
	pm.load()

	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		store:     bs,
		msgs:      ms,
		pm:        pm,
		dataDir:   dataDir,
		quotaPath: filepath.Join(dataDir, quotaFileName),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// ConfigureStorage sets the blockstore size limits and activates the storage
// quota balloon. Safe to call multiple times (e.g. when the user adjusts
// their budget in Settings); the balloon resizes on the next sync tick.
//
//   - limitBytes: total max (0 = use engine default of 10 GiB).
//   - physicalReserveBytes: guaranteed space for locally-authored blocks.
//   - bluetoothReserveBytes: guaranteed space for BT-peer-received blocks.
//
// Relay-received blocks fill the remaining space and are evicted first.
func (e *Engine) ConfigureStorage(limitBytes, physicalReserveBytes, bluetoothReserveBytes int64) {
	if limitBytes <= 0 {
		return
	}
	e.store.WithStorageLimit(limitBytes).WithReservations(map[blockstore.Tag]int64{
		blockstore.TagPhysical:  physicalReserveBytes,
		blockstore.TagBluetooth: bluetoothReserveBytes,
		blockstore.TagLan:       bluetoothReserveBytes / 2,
	})

	// Immediately stamp the quota file at the right size so the OS storage
	// reporter shows the full budget from the moment the user confirms setup.
	e.syncQuotaFile()

	// Launch the background balloon-sync goroutine exactly once.
	e.quotaOnce.Do(func() { go e.runQuotaSync() })
}

// syncQuotaFile sets the quota file's size to (limit - db.Size()), so that
// quota + db ≈ limit in the OS's storage tally.
//
// Growing the file on ext4/f2fs extends it sparsely (no real I/O, no disk
// consumption). Shrinking the file is always instant (ftruncate). The net
// effect: the app appears to "own" exactly limit bytes from day one, and the
// visible footprint never changes as blocks arrive or are evicted.
func (e *Engine) syncQuotaFile() {
	used      := e.store.DiskUsageBytes()
	limit     := e.store.StorageLimitBytes()
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	// Truncate creates the file if it doesn't exist.
	_ = os.Truncate(e.quotaPath, remaining)
}

func (e *Engine) runQuotaSync() {
	ticker := time.NewTicker(quotaSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			e.syncQuotaFile() // final sync before shutdown
			return
		case <-ticker.C:
			e.syncQuotaFile()
		}
	}
}

// DiskUsageBytes returns the current approximate blockstore size on disk in
// bytes. Does not include the quota balloon file.
func (e *Engine) DiskUsageBytes() int64 {
	return e.store.DiskUsageBytes()
}

// StorageLimitBytes returns the configured maximum blockstore size.
// Returns the engine default (10 GiB) if ConfigureStorage has not been called.
func (e *Engine) StorageLimitBytes() int64 {
	return e.store.StorageLimitBytes()
}

// AddPeer adds a relay peer by URL. Returns true if newly added.
func (e *Engine) AddPeer(url string) bool {
	added := e.pm.add(url, "manual")
	if added {
		e.pm.save()
	}
	return added
}

// RemovePeer removes a tracked peer by URL.
func (e *Engine) RemovePeer(url string) {
	e.pm.remove(url)
	e.pm.save()
}

// BlockPeer blocks a peer by URL, preventing sync with it.
func (e *Engine) BlockPeer(url string) {
	e.pm.block(url)
	e.pm.save()
}

// UnblockPeer removes the block on a peer.
func (e *Engine) UnblockPeer(url string) {
	e.pm.unblock(url)
	e.pm.save()
}

// ListPeers returns the tracked peer list as a JSON string.
func (e *Engine) ListPeers() string {
	peers := e.pm.ListPeers()
	b, _ := json.Marshal(peers)
	return string(b)
}

// StartSync begins a background loop that syncs with tracked peers every
// intervalSecs seconds. Safe to call multiple times; only the first call acts.
// SyncNow triggers an immediate sync round outside the normal interval.
// Safe to call at any time; the round runs in its own goroutine.
func (e *Engine) SyncNow() {
	go e.doSyncRound()
}

func (e *Engine) StartSync(intervalSecs int) {
	e.syncOnce.Do(func() {
		go func() {
			e.doSyncRound()
			ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-e.ctx.Done():
					return
				case <-ticker.C:
					e.doSyncRound()
				}
			}
		}()
	})
}

// doSyncRound picks the least-recently-synced non-blocked peer and runs one
// pull+gossip+push cycle with it.
func (e *Engine) doSyncRound() {
	pick := e.pm.pickPeer()
	if pick == "" {
		return
	}
	c := relay.NewClient(pick)
	since := e.pm.lastSync(pick)

	pulledIDs, err := c.Pull(e.ctx, e.store, 0, since)
	if err != nil {
		log.Printf("mobile: sync pull FAILED %s: %v", pick, err)
		e.pm.recordFailure(pick, err.Error())
		return
	}
	log.Printf("mobile: sync pull %s: %d new blocks (since %v)", pick, len(pulledIDs), since)

	// Gossip: register any new peers the relay knows about.
	if gossipURLs, err := c.Hello(e.ctx, ""); err == nil {
		for _, gu := range gossipURLs {
			if e.pm.add(gu, "gossip") {
				log.Printf("mobile: discovered peer via gossip from %s: %s", pick, gu)
			}
		}
	}

	skip := make(map[blockstore.ID]struct{}, len(pulledIDs))
	for _, id := range pulledIDs {
		skip[id] = struct{}{}
	}
	pushed := 0
	syncErr := ""
	if n, err := c.Push(e.ctx, e.store, 0, since, skip); err != nil {
		log.Printf("mobile: sync push FAILED %s: %v", pick, err)
		syncErr = err.Error()
	} else {
		pushed = n
		log.Printf("mobile: sync push %s: %d blocks uploaded", pick, n)
	}

	e.pm.recordSuccess(pick, len(pulledIDs), pushed, syncErr)
	e.pm.save()
}

// StartLANServer starts a relay-protocol HTTP server on the LAN discovery port
// so that other nodes (desktop or Android) can find and sync with this device.
// Call alongside StartLANDiscovery so this device is both discoverable and
// able to discover others.
func (e *Engine) StartLANServer() error {
	srv := relay.NewServer(e.store, 0)
	srv.SetPeerSource(e.pm.activeURLs)
	srv.SetPeerAdder(func(u string) { e.pm.add(u, "lan") })
	addr := fmt.Sprintf("0.0.0.0:%d", lan.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mobile: listen %s: %w", addr, err)
	}
	go func() {
		<-e.ctx.Done()
		l.Close()
	}()
	go http.Serve(l, srv) //nolint:errcheck
	return nil
}

// StartLANDiscovery scans the local network for sneakernet relay nodes every
// intervalSecs seconds and adds discovered peers automatically.
// Safe to call multiple times; only the first call acts.
func (e *Engine) StartLANDiscovery(intervalSecs int) {
	e.lanOnce.Do(func() {
		go func() {
			for addr := range lan.Discover(e.ctx, time.Duration(intervalSecs)*time.Second) {
				peerURL := "http://" + addr
				if e.pm.add(peerURL, "lan") {
					log.Printf("mobile: discovered LAN peer: %s", peerURL)
					e.pm.save()
				}
			}
		}()
	})
}

// StartAPIServer starts the local HTTP API server on addr (e.g. "127.0.0.1:8080").
// keystorePath is the file path for the keystore (created on first run via POST /api/keystore/create).
// The server runs in the background until Close is called.
func (e *Engine) StartAPIServer(addr, keystorePath string) error {
	srv := api.New(e.store, e.msgs, keystorePath)
	srv.SetPeerManager(e.pm)
	srv.SetStatusProvider(e)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mobile: listen %s: %w", addr, err)
	}
	go func() {
		<-e.ctx.Done()
		l.Close()
	}()
	go http.Serve(l, srv) //nolint:errcheck
	return nil
}

// BluetoothPeer abstracts a connected Bluetooth Classic (RFCOMM) socket.
// Implement this in Kotlin/Java using BluetoothSocket.inputStream/outputStream.
// All methods are called from a Go goroutine and must be thread-safe.
type BluetoothPeer interface {
	// Read reads up to len(b) bytes into b. Returns bytes read, or error.
	Read(b []byte) (int, error)
	// Write writes all of b. Returns error on failure.
	Write(b []byte) error
	// Close closes the underlying connection.
	Close() error
}

// btRW bridges BluetoothPeer to io.ReadWriter for the session package.
type btRW struct{ p BluetoothPeer }

func (r btRW) Read(p []byte) (int, error) { return r.p.Read(p) }
func (w btRW) Write(p []byte) (int, error) {
	if err := w.p.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RunBluetoothSession runs a full block-exchange session with a Bluetooth peer,
// then exchanges known internet relay URLs with the peer. Any relay URLs the
// peer shares are automatically added to this node's peer list.
// Call after an RFCOMM connection is established (both as initiator and acceptor).
// Blocks until the session completes or the engine is closed.
// ActiveBTSessions returns the number of Bluetooth sessions currently in progress.
// Implements api.StatusProvider.
func (e *Engine) ActiveBTSessions() int {
	return int(atomic.LoadInt32(&e.activeBTCount))
}

func (e *Engine) RunBluetoothSession(peer BluetoothPeer) error {
	atomic.AddInt32(&e.activeBTCount, 1)
	defer atomic.AddInt32(&e.activeBTCount, -1)
	defer peer.Close()
	discovered, err := bluetooth.Run(e.ctx, btRW{peer}, e.store, e.pm.activeURLs())
	for _, u := range discovered {
		if e.pm.add(u, "bluetooth") {
			log.Printf("mobile: discovered relay via bluetooth gossip: %s", u)
			e.pm.save()
		}
	}
	return err
}

// ServiceUUID returns the Bluetooth SDP / BLE service UUID for sneakernet.
func ServiceUUID() string {
	return bluetooth.ServiceUUID
}

// Close shuts down the engine and releases all resources.
func (e *Engine) Close() error {
	e.cancel()
	if err := e.msgs.Close(); err != nil {
		return err
	}
	return e.store.Close()
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
	"github.com/brendanbenshoof/sneakernet/client/api"
	"github.com/brendanbenshoof/sneakernet/transport/lan"
	"github.com/brendanbenshoof/sneakernet/transport/relay"
)

const maxPeers = 200

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "relay":
		cmdRelay(os.Args[2:])
	case "mass-storage":
		cmdMassStorage(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: snk <subcommand> [flags]\n\nsubcommands:\n  relay          run a sneakernet relay node\n  mass-storage   sync blocks to/from a flat-file mass storage volume\n")
}

func cmdMassStorage(args []string) {
	fs := flag.NewFlagSet("mass-storage", flag.ExitOnError)
	srcSQLite := fs.String("from-sqlite", "", "source SQLite blockstore path (blocks.db)")
	srcBadger  := fs.String("from-badger", "", "source BadgerDB blockstore directory")
	targetDir  := fs.String("to", "", "target flat-file mass storage directory (required)")
	reindex    := fs.Bool("reindex", false, "rebuild index only, do not sync blocks")
	fs.Parse(args)

	if *targetDir == "" {
		fmt.Fprintln(os.Stderr, "mass-storage: -to <dir> is required")
		fs.Usage()
		os.Exit(1)
	}

	target, err := blockstore.OpenFlatFile(*targetDir)
	if err != nil {
		log.Fatalf("open flat-file store: %v", err)
	}
	defer target.Close()

	if !*reindex {
		var src blockstore.Store
		switch {
		case *srcSQLite != "":
			s, err := blockstore.OpenSQLite(*srcSQLite)
			if err != nil {
				log.Fatalf("open sqlite source: %v", err)
			}
			defer s.Close()
			src = s
		case *srcBadger != "":
			s, err := blockstore.OpenBadger(*srcBadger)
			if err != nil {
				log.Fatalf("open badger source: %v", err)
			}
			defer s.Close()
			src = s
		default:
			fmt.Fprintln(os.Stderr, "mass-storage: one of -from-sqlite or -from-badger is required unless -reindex is set")
			fs.Usage()
			os.Exit(1)
		}

		if err := syncToFlatFile(src, target); err != nil {
			log.Fatalf("sync: %v", err)
		}
	}

	log.Println("building index...")
	if err := blockstore.BuildIndex(*targetDir); err != nil {
		log.Fatalf("build index: %v", err)
	}
	log.Println("done")
}

func syncToFlatFile(src blockstore.Store, dst *blockstore.FlatFileStore) error {
	token := ""
	copied, skipped, errs := 0, 0, 0
	for {
		next, refs, err := src.ListBlocks(token, 500, 0, time.Time{})
		if err != nil {
			return fmt.Errorf("list blocks: %w", err)
		}
		for _, ref := range refs {
			stamp, payload, err := src.Get(ref.ID)
			if err != nil {
				errs++
				continue
			}
			already, err := dst.Has(ref.ID)
			if err != nil {
				errs++
				continue
			}
			if already {
				skipped++
				continue
			}
			if _, err := dst.Put(stamp, payload); err != nil {
				errs++
				continue
			}
			copied++
		}
		if next == "" {
			break
		}
		token = next
		log.Printf("synced %d blocks so far...", copied)
	}
	log.Printf("sync complete: %d copied, %d already present, %d errors", copied, skipped, errs)
	return nil
}

func cmdRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr         := fs.String("addr", "127.0.0.1:8080", "user API listen address")
	relayAddr    := fs.String("relay-addr", "0.0.0.0:8081", "relay listen address")
	blocksDir    := fs.String("blocks", "blocks.db", "blockstore directory path")
	messagesDB   := fs.String("messages", "messages.db", "message store SQLite path")
	keystoreFile := fs.String("keystore", "keystore.json", "keystore file path")
	powFloor     := fs.Int("pow-floor", 0, "minimum proof-of-work for relay block acceptance")
	syncInterval := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	peersFlag    := fs.String("peers", "", "comma-separated list of peer base URLs to always sync with (e.g. https://relay.example.com,http://peer2.local:8081)")
	lanScan      := fs.Bool("lan", false, fmt.Sprintf("scan LAN for sneakernet peers on port %d (\"snk\" in base32)", lan.Port))
	fs.Parse(args)

	var staticPeers []string
	if *peersFlag != "" {
		for _, p := range strings.Split(*peersFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				staticPeers = append(staticPeers, p)
			}
		}
	}

	bs, err := blockstore.OpenBadger(*blocksDir)
	if err != nil {
		log.Fatalf("open blockstore: %v", err)
	}
	defer bs.Close()

	ms, err := client.OpenMessageStore(*messagesDB)
	if err != nil {
		log.Fatalf("open message store: %v", err)
	}
	defer ms.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pt := newPeerTracker()

	// Relay server: block exchange with other sneakernet nodes.
	relaySrv := relay.NewServer(bs, *powFloor)
	relaySrv.SetPeerSource(pt.nonPenalizedPeers)
	go func() {
		if err := http.ListenAndServe(*relayAddr, relaySrv); err != nil {
			log.Printf("relay server stopped: %v", err)
		}
	}()
	log.Printf("Relay listening at %s", *relayAddr)

	// Collect peer addresses from LAN discovery (if enabled).
	var peerSources []<-chan string
	if *lanScan {
		log.Printf("LAN scan enabled (port %d)", lan.Port)
		peerSources = append(peerSources, lan.Discover(ctx, *syncInterval))
	}

	// Sync loop: exchange blocks with known peers and gossip to discover more.
	go pt.run(ctx, bs, mergePeers(ctx, peerSources...), *powFloor, *syncInterval, staticPeers)

	// User-facing API server.
	apiSrv := api.New(bs, ms, *keystoreFile)
	fmt.Printf("Sneakernet running at http://%s\n", *addr)
	go func() {
		if err := http.ListenAndServe(*addr, apiSrv); err != nil {
			log.Printf("api server stopped: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
}

// mergePeers fans in multiple peer address channels into one.
func mergePeers(ctx context.Context, sources ...<-chan string) <-chan string {
	out := make(chan string, 16)
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			for {
				select {
				case addr, ok := <-ch:
					if !ok {
						return
					}
					select {
					case out <- addr:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}(src)
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

// peerURL constructs the base URL for a peer.
// Input may be a full URL (http/https scheme) or a bare host:port from LAN discovery.
// Port 443 is assumed TLS; all others use plain HTTP.
func peerURL(hostport string) string {
	if strings.HasPrefix(hostport, "http://") || strings.HasPrefix(hostport, "https://") {
		// Already a full URL — validate and normalise.
		u, err := url.Parse(hostport)
		if err == nil && u.Host != "" {
			return strings.TrimRight(hostport, "/")
		}
	}
	// Bare host:port (e.g. from LAN discovery).
	_, port, _ := net.SplitHostPort(hostport)
	if port == "443" {
		return "https://" + hostport
	}
	return "http://" + hostport
}

const maxBackoffRounds = 64

type peerState struct {
	skipRounds int       // rounds remaining before next attempt
	failures   int       // consecutive failed attempts
	pullSince  time.Time // cursor: only pull blocks created after this time
	pushSince  time.Time // cursor: only push blocks created after this time
}

type peerTracker struct {
	mu    sync.Mutex
	known map[string]*peerState
}

func newPeerTracker() *peerTracker {
	return &peerTracker{known: make(map[string]*peerState, maxPeers)}
}

// nonPenalizedPeers returns base URLs of peers not currently in backoff,
// excluding private/LAN addresses so internal IPs are never gossiped to the internet.
// DNS hostnames are assumed public and always included.
// Used by the relay's GET /v1/peers gossip endpoint.
func (pt *peerTracker) nonPenalizedPeers() []string {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	var out []string
	for u, st := range pt.known {
		if st.skipRounds == 0 && isPublicURL(u) {
			out = append(out, u)
		}
	}
	return out
}

// isPublicURL returns false if the URL's host is a private, loopback, or
// link-local IP address. DNS hostnames are considered public.
func isPublicURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return true // DNS hostname — assume public
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// addPeer registers a peer URL. Returns true if it was newly added.
func (pt *peerTracker) addPeer(u string) bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if _, exists := pt.known[u]; !exists && len(pt.known) < maxPeers {
		pt.known[u] = &peerState{}
		return true
	}
	return false
}

func (pt *peerTracker) syncOne(ctx context.Context, store blockstore.Store, u string, powFloor int) {
	pt.mu.Lock()
	st, ok := pt.known[u]
	if !ok {
		pt.mu.Unlock()
		return
	}
	pullSince := st.pullSince
	pushSince := st.pushSince
	pt.mu.Unlock()

	c := relay.NewClient(u)

	pullStart := time.Now()
	n, err := c.Pull(ctx, store, powFloor, pullSince)

	pt.mu.Lock()
	if st, ok := pt.known[u]; ok {
		if err != nil {
			log.Printf("sync pull %s: %v", u, err)
			st.failures++
			rounds := 1 << st.failures
			if rounds > maxBackoffRounds {
				rounds = maxBackoffRounds
			}
			st.skipRounds = rounds
			log.Printf("peer %s unreachable (failures: %d, retry in %d rounds)", u, st.failures, st.skipRounds)
		} else {
			if n > 0 {
				log.Printf("sync pull %s: %d new blocks", u, n)
			}
			if st.failures > 0 {
				log.Printf("peer %s recovered", u)
			}
			st.failures = 0
			st.skipRounds = 0
			st.pullSince = pullStart
		}
	}
	pt.mu.Unlock()

	if err != nil {
		return
	}

	// Gossip: ask this peer for its known healthy peers and add any we don't know.
	if gossipPeers, err := c.GetPeers(ctx); err == nil {
		for _, p := range gossipPeers {
			p = peerURL(p) // normalise in case peer sends bare host:port
			if pt.addPeer(p) {
				log.Printf("discovered peer via gossip from %s: %s", u, p)
				go pt.syncOne(ctx, store, p, powFloor)
			}
		}
	}

	pushStart := time.Now()
	if n, err := c.Push(ctx, store, powFloor, pushSince); err != nil {
		log.Printf("sync push %s: %v", u, err)
	} else {
		if n > 0 {
			log.Printf("sync push %s: %d blocks uploaded", u, n)
		}
		pt.mu.Lock()
		if st, ok := pt.known[u]; ok {
			st.pushSince = pushStart
		}
		pt.mu.Unlock()
	}
}

// run is the main peer-sync loop. It seeds static peers, then processes
// newly discovered peers from the channel and fires periodic sync rounds.
func (pt *peerTracker) run(ctx context.Context, store blockstore.Store, peers <-chan string, powFloor int, interval time.Duration, staticPeers []string) {
	for _, u := range staticPeers {
		u = peerURL(u)
		pt.addPeer(u)
		log.Printf("static peer: %s", u)
		go pt.syncOne(ctx, store, u, powFloor)
	}

	doSync := func() {
		pt.mu.Lock()
		var ready []string
		for u, st := range pt.known {
			if st.skipRounds > 0 {
				st.skipRounds--
				log.Printf("skipping peer %s (backoff: %d rounds remaining, %d failures)", u, st.skipRounds, st.failures)
				continue
			}
			ready = append(ready, u)
		}
		pt.mu.Unlock()

		for _, u := range ready {
			if ctx.Err() != nil {
				return
			}
			pt.syncOne(ctx, store, u, powFloor)
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case addr, ok := <-peers:
			if !ok {
				peers = nil
				continue
			}
			u := peerURL(addr)
			if pt.addPeer(u) {
				log.Printf("discovered peer: %s", u)
				go pt.syncOne(ctx, store, u, powFloor)
			}
		case <-ticker.C:
			doSync()
		}
	}
}

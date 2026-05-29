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
	"path/filepath"
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
	case "node":
		cmdNode(os.Args[2:])
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
	fmt.Fprintf(os.Stderr, `usage: snk <subcommand> [flags]

subcommands:
  node          run a sneakernet node (behind NAT; dials relays, serves local API)
  relay         run a sneakernet relay (public server; accepts peers, serves webapp)
  mass-storage  sync blocks to/from a flat-file mass storage volume
`)
}

// cmdNode runs a personal node: it dials relay peers to sync blocks and serves
// the authenticated local API (keystore, identities, messages).
func cmdNode(args []string) {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	apiAddr      := fs.String("api-addr", "127.0.0.1:8080", "local API listen address")
	blocksDir    := fs.String("blocks", "blocks.db", "blockstore directory path")
	messagesDB   := fs.String("messages", "messages.db", "message store SQLite path")
	keystoreFile := fs.String("keystore", "keystore.json", "keystore file path")
	powFloor     := fs.Int("pow-floor", 0, "minimum proof-of-work to accept from peers")
	syncInterval := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	peersFlag    := fs.String("peers", "", "comma-separated relay base URLs to sync with (e.g. https://relay.example.com)")
	lanScan      := fs.Bool("lan", false, fmt.Sprintf("scan LAN for sneakernet peers on port %d", lan.Port))
	usbDir       := fs.String("usb-dir", "", "path to sneakernet USB volume root; syncs when .sneakernet marker is present (empty = disabled)")
	usbInterval  := fs.Duration("usb-interval", 30*time.Second, "how often to check and sync the USB volume")
	storageLimit    := fs.String("storage-limit", "0", "maximum blockstore size (e.g. 10GB, 512MB); 0 = unlimited")
	reservePhysical := fs.String("reserve-physical", "0", "storage reserved for physical/local blocks (e.g. 2GB)")
	reserveLan      := fs.String("reserve-lan", "0", "storage reserved for LAN peer blocks")
	fs.Parse(args)

	staticPeers := splitPeers(*peersFlag)

	bs, err := blockstore.OpenBadger(*blocksDir)
	if err != nil {
		log.Fatalf("open blockstore: %v", err)
	}
	defer bs.Close()

	if limit, err := parseBytes(*storageLimit); err != nil {
		log.Fatalf("invalid -storage-limit: %v", err)
	} else if limit > 0 {
		physical, err := parseBytes(*reservePhysical)
		if err != nil {
			log.Fatalf("invalid -reserve-physical: %v", err)
		}
		lan_, err := parseBytes(*reserveLan)
		if err != nil {
			log.Fatalf("invalid -reserve-lan: %v", err)
		}
		bs.WithStorageLimit(limit).WithReservations(map[blockstore.Tag]int64{
			blockstore.TagPhysical: physical,
			blockstore.TagLan:      lan_,
		})
	}

	ms, err := client.OpenMessageStore(*messagesDB)
	if err != nil {
		log.Fatalf("open message store: %v", err)
	}
	defer ms.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pt := newPeerTracker()

	var peerSources []<-chan string
	if *lanScan {
		log.Printf("LAN scan enabled (port %d)", lan.Port)
		peerSources = append(peerSources, lan.Discover(ctx, *syncInterval))
	}

	go pt.run(ctx, bs, mergePeers(ctx, peerSources...), *powFloor, *syncInterval, staticPeers)

	if *usbDir != "" {
		go usbSyncLoop(ctx, bs, *usbDir, *usbInterval)
	}

	apiSrv := api.New(bs, ms, *keystoreFile)
	fmt.Printf("Sneakernet node running at http://%s\n", *apiAddr)
	go func() {
		if err := http.ListenAndServe(*apiAddr, apiSrv); err != nil {
			log.Printf("api server stopped: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
}

// cmdRelay runs a public relay: it accepts inbound block-exchange connections,
// peers with other relays, and serves the browser webapp.
func cmdRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr            := fs.String("addr", "0.0.0.0:8081", "relay listen address")
	blocksDir       := fs.String("blocks", "blocks.db", "blockstore directory path")
	powFloor        := fs.Int("pow-floor", 0, "minimum proof-of-work for block acceptance")
	syncInterval    := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	peersFlag       := fs.String("peers", "", "comma-separated peer relay base URLs (e.g. https://relay.example.com)")
	lanScan         := fs.Bool("lan", false, fmt.Sprintf("scan LAN for sneakernet peers on port %d", lan.Port))
	storageLimit    := fs.String("storage-limit", "0", "maximum blockstore size (e.g. 10GB, 512MB); 0 = unlimited")
	reservePhysical := fs.String("reserve-physical", "0", "storage reserved for physical/local blocks (e.g. 2GB)")
	reserveLan      := fs.String("reserve-lan", "0", "storage reserved for LAN peer blocks")
	reserveRegional := fs.String("reserve-regional", "0", "storage reserved for regional peer blocks")
	reserveGlobal   := fs.String("reserve-global", "0", "storage reserved for global relay blocks")
	regionFlag      := fs.String("region", "", "ISO 3166 codes this relay serves, e.g. US-GA,CA; enables regional tagging")
	geoipDB         := fs.String("geoip-db", "", "path to cache the GeoIP MMDB (default: <blocks-dir>/geoip.mmdb)")
	geoipURL        := fs.String("geoip-url", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb", "URL to download GeoLite2-City MMDB")
	geoipRefresh    := fs.Duration("geoip-refresh", 120*time.Hour, "how often to refresh the GeoIP database")
	fs.Parse(args)

	staticPeers := splitPeers(*peersFlag)

	bs, err := blockstore.OpenBadger(*blocksDir)
	if err != nil {
		log.Fatalf("open blockstore: %v", err)
	}
	defer bs.Close()

	if limit, err := parseBytes(*storageLimit); err != nil {
		log.Fatalf("invalid -storage-limit: %v", err)
	} else if limit > 0 {
		physical, err := parseBytes(*reservePhysical)
		if err != nil {
			log.Fatalf("invalid -reserve-physical: %v", err)
		}
		lan_, err := parseBytes(*reserveLan)
		if err != nil {
			log.Fatalf("invalid -reserve-lan: %v", err)
		}
		regional, err := parseBytes(*reserveRegional)
		if err != nil {
			log.Fatalf("invalid -reserve-regional: %v", err)
		}
		global, err := parseBytes(*reserveGlobal)
		if err != nil {
			log.Fatalf("invalid -reserve-global: %v", err)
		}
		bs.WithStorageLimit(limit).WithReservations(map[blockstore.Tag]int64{
			blockstore.TagPhysical: physical,
			blockstore.TagLan:      lan_,
			blockstore.TagRegional: regional,
			blockstore.TagGlobal:   global,
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pt := newPeerTracker()

	relaySrv := relay.NewServer(bs, *powFloor)
	relaySrv.SetPeerSource(pt.nonPenalizedPeers)
	if *regionFlag != "" {
		dbPath := *geoipDB
		if dbPath == "" {
			dbPath = filepath.Join(*blocksDir, "geoip.mmdb")
		}
		var regions []string
		for _, r := range strings.Split(*regionFlag, ",") {
			if r = strings.TrimSpace(r); r != "" {
				regions = append(regions, r)
			}
		}
		g := relay.NewGeoIP(dbPath, *geoipURL, regions, *geoipRefresh)
		g.Start(ctx)
		relaySrv.SetGeoIP(g)
		log.Printf("regional tagging enabled: %s", *regionFlag)
	}
	go func() {
		if err := http.ListenAndServe(*addr, relaySrv); err != nil {
			log.Printf("relay server stopped: %v", err)
		}
	}()
	log.Printf("Relay listening at %s", *addr)

	var peerSources []<-chan string
	if *lanScan {
		log.Printf("LAN scan enabled (port %d)", lan.Port)
		peerSources = append(peerSources, lan.Discover(ctx, *syncInterval))
	}

	go pt.run(ctx, bs, mergePeers(ctx, peerSources...), *powFloor, *syncInterval, staticPeers)

	<-ctx.Done()
	log.Println("shutting down")
}

func cmdMassStorage(args []string) {
	fs := flag.NewFlagSet("mass-storage", flag.ExitOnError)
	srcBadger := fs.String("from-badger", "", "source BadgerDB blockstore directory")
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
		if *srcBadger == "" {
			fmt.Fprintln(os.Stderr, "mass-storage: -from-badger is required unless -reindex is set")
			fs.Usage()
			os.Exit(1)
		}
		var src blockstore.Store
		{
			s, err := blockstore.OpenBadger(*srcBadger)
			if err != nil {
				log.Fatalf("open badger source: %v", err)
			}
			defer s.Close()
			src = s
		}

		if err := syncStores(src, target); err != nil {
			log.Fatalf("sync: %v", err)
		}
	}

	log.Println("building index...")
	if err := blockstore.BuildIndex(*targetDir); err != nil {
		log.Fatalf("build index: %v", err)
	}
	log.Println("done")
}

func syncStores(src, dst blockstore.Store) error {
	token := ""
	copied, skipped, errs := 0, 0, 0
	var firstErr error
	for {
		next, refs, err := src.ListBlocks(token, 500, 0, time.Time{})
		if err != nil {
			return fmt.Errorf("list blocks: %w", err)
		}
		for _, ref := range refs {
			stamp, payload, err := src.Get(ref.ID)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("get %x: %w", ref.ID[:4], err)
				}
				errs++
				continue
			}
			already, err := dst.Has(ref.ID)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("has %x: %w", ref.ID[:4], err)
				}
				errs++
				continue
			} else if already {
				// Still copy if src has a higher work_factor (boosted block).
				dstWF, err := dst.GetWorkFactor(ref.ID)
				if err != nil || ref.WorkFactor <= dstWF {
					skipped++
					continue
				}
			}
			if _, err := dst.Put(stamp, payload, blockstore.TagPhysical); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("put %x: %w", ref.ID[:4], err)
				}
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
	if errs > 0 {
		log.Printf("sync complete: %d copied, %d already present, %d errors (first: %v)", copied, skipped, errs, firstErr)
	} else {
		log.Printf("sync complete: %d copied, %d already present, %d errors", copied, skipped, errs)
	}
	return nil
}

func usbSyncLoop(ctx context.Context, store blockstore.Store, dir string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			entries, err := os.ReadDir(dir)
			if err != nil {
				log.Printf("usb sync: readdir %s: %v", dir, err)
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				volDir := filepath.Join(dir, e.Name())
				if _, err := os.Stat(filepath.Join(volDir, ".sneakernet")); err != nil {
					continue
				}
				usb, err := blockstore.OpenFlatFile(volDir)
				if err != nil {
					log.Printf("usb sync: open %s: %v", volDir, err)
					continue
				}
				log.Printf("usb sync: syncing with %s", volDir)
				if err := syncStores(usb, store); err != nil {
					log.Printf("usb sync: pull from %s: %v", volDir, err)
				}
				if err := syncStores(store, usb); err != nil {
					log.Printf("usb sync: push to %s: %v", volDir, err)
				}
				usb.Close()
			}
		}
	}
}

// splitPeers parses a comma-separated peer URL list into a slice of base URLs.
func splitPeers(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
		u, err := url.Parse(hostport)
		if err == nil && u.Host != "" {
			return strings.TrimRight(hostport, "/")
		}
	}
	_, port, _ := net.SplitHostPort(hostport)
	if port == "443" {
		return "https://" + hostport
	}
	return "http://" + hostport
}

const maxBackoffRounds = 64

type peerState struct {
	skipRounds int
	failures   int
	pullSince  time.Time
	pushSince  time.Time
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

func isPublicURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

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

	if gossipPeers, err := c.GetPeers(ctx); err == nil {
		for _, p := range gossipPeers {
			p = peerURL(p)
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

// parseBytes parses a human-readable byte size string into an int64.
// Accepts plain integers or values with SI suffixes: KB, MB, GB, TB (case-insensitive).
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
	}
	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, sf.suffix) {
			numStr := strings.TrimSpace(s[:len(s)-len(sf.suffix)])
			var n int64
			if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil {
				return 0, fmt.Errorf("cannot parse %q", s)
			}
			return n * sf.mult, nil
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("cannot parse %q", s)
	}
	return n, nil
}

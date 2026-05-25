package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
	"github.com/brendanbenshoof/sneakernet/client/api"
	"github.com/brendanbenshoof/sneakernet/transport/dht"
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
	srcSQLite  := fs.String("from-sqlite", "", "source SQLite blockstore path (blocks.db)")
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
	addr          := fs.String("addr", "127.0.0.1:8080", "user API listen address")
	relayAddr     := fs.String("relay-addr", "0.0.0.0:8081", "relay listen address")
	advertiseAddr := fs.String("advertise-addr", "", "host:port to advertise to peers via DHT (overrides relay-addr; use when behind a proxy)")
	blocksDir     := fs.String("blocks", "blocks.db", "blockstore directory path")
	messagesDB    := fs.String("messages", "messages.db", "message store SQLite path")
	keystoreFile  := fs.String("keystore", "keystore.json", "keystore file path")
	powFloor      := fs.Int("pow-floor", 0, "minimum proof-of-work for relay block acceptance")
	syncInterval  := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	peersFlag     := fs.String("peers", "", "comma-separated list of peer base URLs to always sync with (e.g. https://relay.example.com)")
	lanScan       := fs.Bool("lan", false, fmt.Sprintf("scan LAN for sneakernet peers on port %d (\"snk\" in base32)", lan.Port))
	fs.Parse(args)

	var staticPeers []string
	if *peersFlag != "" {
		for _, p := range strings.Split(*peersFlag, ",") {
			if p = strings.TrimSpace(p); p != "" {
				staticPeers = append(staticPeers, p)
			}
		}
	}

	_, portStr, err := net.SplitHostPort(*relayAddr)
	if err != nil {
		log.Fatalf("invalid relay-addr %q: %v", *relayAddr, err)
	}
	relayPort, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("invalid relay port %q: %v", portStr, err)
	}

	dhtPort := relayPort
	if *advertiseAddr != "" {
		_, advPortStr, err := net.SplitHostPort(*advertiseAddr)
		if err != nil {
			log.Fatalf("invalid advertise-addr %q: %v", *advertiseAddr, err)
		}
		dhtPort, err = strconv.Atoi(advPortStr)
		if err != nil {
			log.Fatalf("invalid port in advertise-addr %q: %v", *advertiseAddr, err)
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

	// Relay server: block exchange with other sneakernet nodes.
	relaySrv := relay.NewServer(bs, *powFloor)
	go func() {
		if err := http.ListenAndServe(*relayAddr, relaySrv); err != nil {
			log.Printf("relay server stopped: %v", err)
		}
	}()

	// DHT: advertise our relay port under the shared sneakernet info-hash.
	if *advertiseAddr != "" {
		log.Printf("Relay listening at %s, advertised as %s", *relayAddr, *advertiseAddr)
	} else {
		log.Printf("Relay listening at %s", *relayAddr)
	}
	disc, err := dht.New(dhtPort)
	if err != nil {
		log.Fatalf("dht init: %v", err)
	}
	go func() {
		if err := disc.Start(ctx); err != nil && err != context.Canceled {
			log.Printf("dht: %v", err)
		}
	}()

	// Collect peer addresses from all discovery sources.
	peerSources := []<-chan string{disc.Peers()}
	if *lanScan {
		log.Printf("LAN scan enabled (port %d)", lan.Port)
		peerSources = append(peerSources, lan.Discover(ctx, *syncInterval))
	}

	// Sync loop: collect discovered peers and exchange blocks with them.
	go syncPeers(ctx, bs, mergePeers(ctx, peerSources...), *powFloor, *syncInterval, staticPeers)

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

// peerURL constructs the base URL for a peer given its "host:port" address.
// Port 443 is assumed to be TLS-terminated; all others use plain HTTP.
func peerURL(hostport string) string {
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

// syncPeers collects relay addresses from DHT discovery and periodically
// pushes and pulls blocks to/from each known peer.
// known stores full base URLs; staticPeers are pre-seeded and never evicted.
func syncPeers(ctx context.Context, store blockstore.Store, peers <-chan string, powFloor int, interval time.Duration, staticPeers []string) {
	var mu sync.Mutex
	known := make(map[string]*peerState, maxPeers)

	syncOne := func(u string) {
		// Read cursors under lock; do network I/O without holding it.
		mu.Lock()
		st, ok := known[u]
		if !ok {
			mu.Unlock()
			return
		}
		pullSince := st.pullSince
		pushSince := st.pushSince
		mu.Unlock()

		c := relay.NewClient(u)

		pullStart := time.Now()
		n, err := c.Pull(ctx, store, powFloor, pullSince)

		mu.Lock()
		if st, ok := known[u]; ok {
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
		mu.Unlock()

		if err != nil {
			return
		}

		pushStart := time.Now()
		if n, err := c.Push(ctx, store, powFloor, pushSince); err != nil {
			log.Printf("sync push %s: %v", u, err)
		} else {
			if n > 0 {
				log.Printf("sync push %s: %d blocks uploaded", u, n)
			}
			mu.Lock()
			if st, ok := known[u]; ok {
				st.pushSince = pushStart
			}
			mu.Unlock()
		}
	}

	addPeer := func(u string) (isNew bool) {
		mu.Lock()
		defer mu.Unlock()
		if _, exists := known[u]; !exists && len(known) < maxPeers {
			known[u] = &peerState{}
			return true
		}
		return false
	}

	for _, u := range staticPeers {
		addPeer(u)
		log.Printf("static peer: %s", u)
		go syncOne(u)
	}

	doSync := func() {
		mu.Lock()
		type entry struct {
			url string
			st  *peerState
		}
		var ready []string
		for u, st := range known {
			if st.skipRounds > 0 {
				st.skipRounds--
				log.Printf("skipping peer %s (backoff: %d rounds remaining, %d failures)", u, st.skipRounds, st.failures)
				continue
			}
			ready = append(ready, u)
		}
		mu.Unlock()

		for _, u := range ready {
			if ctx.Err() != nil {
				return
			}
			syncOne(u)
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case addr := <-peers:
			u := peerURL(addr)
			if addPeer(u) {
				log.Printf("discovered peer: %s", u)
				go syncOne(u)
			}
		case <-ticker.C:
			doSync()
		}
	}
}

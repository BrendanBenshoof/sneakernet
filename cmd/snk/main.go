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
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: snk <subcommand> [flags]\n\nsubcommands:\n  relay   run a sneakernet relay node\n")
}

func cmdRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr          := fs.String("addr", "127.0.0.1:8080", "user API listen address")
	relayAddr     := fs.String("relay-addr", "0.0.0.0:8081", "relay listen address")
	advertiseAddr := fs.String("advertise-addr", "", "host:port to advertise to peers via DHT (overrides relay-addr; use when behind a proxy)")
	blocksDB      := fs.String("blocks", "blocks.db", "blockstore SQLite path")
	messagesDB    := fs.String("messages", "messages.db", "message store SQLite path")
	keystoreFile  := fs.String("keystore", "keystore.json", "keystore file path")
	powFloor      := fs.Int("pow-floor", 0, "minimum proof-of-work for relay block acceptance")
	syncInterval  := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	peersFlag     := fs.String("peers", "", "comma-separated list of peer base URLs to always sync with (e.g. https://relay.example.com)")
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

	bs, err := blockstore.OpenSQLite(*blocksDB)
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

	// Sync loop: collect DHT-discovered peers and exchange blocks with them.
	go syncPeers(ctx, bs, disc.Peers(), *powFloor, *syncInterval, staticPeers)

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
	skipRounds int // rounds remaining before next attempt
	failures   int // consecutive failed attempts
}

// syncPeers collects relay addresses from DHT discovery and periodically
// pushes and pulls blocks to/from each known peer.
// known stores full base URLs; staticPeers are pre-seeded and never evicted.
func syncPeers(ctx context.Context, store blockstore.Store, peers <-chan string, powFloor int, interval time.Duration, staticPeers []string) {
	var mu sync.Mutex
	known := make(map[string]*peerState, maxPeers)

	recordResult := func(u string, err error) {
		mu.Lock()
		defer mu.Unlock()
		st, ok := known[u]
		if !ok {
			return
		}
		if err != nil {
			st.failures++
			rounds := 1 << st.failures
			if rounds > maxBackoffRounds {
				rounds = maxBackoffRounds
			}
			st.skipRounds = rounds
			log.Printf("peer %s unreachable (failures: %d, retry in %d rounds)", u, st.failures, st.skipRounds)
		} else {
			if st.failures > 0 {
				log.Printf("peer %s recovered", u)
			}
			st.failures = 0
			st.skipRounds = 0
		}
	}

	syncOne := func(u string) {
		c := relay.NewClient(u)
		n, err := c.Pull(ctx, store, powFloor, time.Time{})
		if err != nil {
			log.Printf("sync pull %s: %v", u, err)
			recordResult(u, err)
			return
		}
		if n > 0 {
			log.Printf("sync pull %s: %d new blocks", u, n)
		}
		if n, err := c.Push(ctx, store, powFloor, time.Time{}); err != nil {
			log.Printf("sync push %s: %v", u, err)
		} else if n > 0 {
			log.Printf("sync push %s: %d blocks uploaded", u, n)
		}
		recordResult(u, nil)
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

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
	addr         := fs.String("addr", "127.0.0.1:8080", "user API listen address")
	relayAddr    := fs.String("relay-addr", "0.0.0.0:8081", "relay listen address (must be reachable by other nodes)")
	blocksDB     := fs.String("blocks", "blocks.db", "blockstore SQLite path")
	messagesDB   := fs.String("messages", "messages.db", "message store SQLite path")
	keystoreFile := fs.String("keystore", "keystore.json", "keystore file path")
	powFloor     := fs.Int("pow-floor", 0, "minimum proof-of-work for relay block acceptance")
	syncInterval := fs.Duration("sync-interval", 5*time.Minute, "interval between peer sync rounds")
	fs.Parse(args)

	_, portStr, err := net.SplitHostPort(*relayAddr)
	if err != nil {
		log.Fatalf("invalid relay-addr %q: %v", *relayAddr, err)
	}
	relayPort, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("invalid relay port %q: %v", portStr, err)
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
		log.Printf("Relay listening at %s", *relayAddr)
		if err := http.ListenAndServe(*relayAddr, relaySrv); err != nil {
			log.Printf("relay server stopped: %v", err)
		}
	}()

	// DHT: advertise our relay port under the shared sneakernet info-hash.
	disc, err := dht.New(relayPort)
	if err != nil {
		log.Fatalf("dht init: %v", err)
	}
	go func() {
		if err := disc.Start(ctx); err != nil && err != context.Canceled {
			log.Printf("dht: %v", err)
		}
	}()

	// Sync loop: collect DHT-discovered peers and exchange blocks with them.
	go syncPeers(ctx, bs, disc.Peers(), *powFloor, *syncInterval)

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

// syncPeers collects relay addresses from DHT discovery and periodically
// pushes and pulls blocks to/from each known peer.
func syncPeers(ctx context.Context, store blockstore.Store, peers <-chan string, powFloor int, interval time.Duration) {
	var mu sync.RWMutex
	known := make(map[string]struct{}, maxPeers)

	doSync := func() {
		mu.RLock()
		addrs := make([]string, 0, len(known))
		for addr := range known {
			addrs = append(addrs, addr)
		}
		mu.RUnlock()

		for _, addr := range addrs {
			if ctx.Err() != nil {
				return
			}
			c := relay.NewClient("http://" + addr)
			if n, err := c.Pull(ctx, store, powFloor, time.Time{}); err != nil {
				log.Printf("sync pull %s: %v", addr, err)
			} else if n > 0 {
				log.Printf("sync pull %s: %d new blocks", addr, n)
			}
			if n, err := c.Push(ctx, store, powFloor, time.Time{}); err != nil {
				log.Printf("sync push %s: %v", addr, err)
			} else if n > 0 {
				log.Printf("sync push %s: %d blocks uploaded", addr, n)
			}
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case addr := <-peers:
			mu.Lock()
			if len(known) < maxPeers {
				if _, exists := known[addr]; !exists {
					known[addr] = struct{}{}
					log.Printf("discovered peer: %s", addr)
				}
			}
			mu.Unlock()
		case <-ticker.C:
			doSync()
		}
	}
}

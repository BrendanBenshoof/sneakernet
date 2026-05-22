package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/client"
	"github.com/brendanbenshoof/sneakernet/client/api"
)

func main() {
	addr      := flag.String("addr", "127.0.0.1:8080", "listen address")
	blocksDB  := flag.String("blocks", "blocks.db", "blockstore SQLite path")
	messagesDB := flag.String("messages", "messages.db", "message store SQLite path")
	keystoreFile := flag.String("keystore", "keystore.json", "keystore file path")
	flag.Parse()

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

	srv := api.New(bs, ms, *keystoreFile)

	fmt.Printf("Sneakernet running at http://%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv))
}

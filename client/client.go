package client

import (
	"context"
	"crypto/ecdh"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const scrapePageSize = 100

// Client scrapes a blockstore for messages addressed to any of its held keys.
type Client struct {
	blocks   blockstore.Store
	messages *MessageStore
	privKeys []*ecdh.PrivateKey
}

// New creates a Client. Pass one key per identity; all are tried on every block.
func New(blocks blockstore.Store, messages *MessageStore, privKeys ...*ecdh.PrivateKey) *Client {
	return &Client{blocks: blocks, messages: messages, privKeys: privKeys}
}

// Scrape pages through all blocks added since the last checkpoint, attempts
// decryption on each, and persists any that are addressed to this client.
// Returns the number of new messages found. The checkpoint advances to the
// moment just before the scan began, so subsequent calls only process new blocks.
func (c *Client) Scrape(ctx context.Context) (int, error) {
	since, err := c.messages.GetCheckpoint()
	if err != nil {
		return 0, err
	}
	scanStart := time.Now()

	var (
		pageToken string
		found     int
	)
	for {
		if err := ctx.Err(); err != nil {
			return found, err
		}

		nextToken, refs, err := c.blocks.ListBlocks(pageToken, scrapePageSize, 0, since)
		if err != nil {
			return found, err
		}

		for _, ref := range refs {
			_, payload, err := c.blocks.Get(ref.ID)
			if err != nil {
				continue // block expired between list and get
			}
			mp, ok := c.tryAllKeys(payload)
			if !ok {
				continue
			}

			var inserted bool
			if mp.IsFragment() {
				inserted, err = c.messages.SaveFragment(ref.ID, mp)
			} else {
				inserted, err = c.messages.SaveMessage(ref.ID, mp)
			}
			if err != nil {
				return found, err
			}
			if inserted {
				found++
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return found, c.messages.SetCheckpoint(scanStart)
}

// tryAllKeys attempts decryption with each held private key.
// Returns the MessagePayload and true on the first success.
func (c *Client) tryAllKeys(payload blockstore.Payload) (MessagePayload, bool) {
	for _, key := range c.privKeys {
		if mp, err := tryDecrypt(key, payload); err == nil {
			return mp, true
		}
	}
	return MessagePayload{}, false
}

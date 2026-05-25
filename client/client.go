package client

import (
	"context"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

const scrapePageSize = 100

// Client scrapes a blockstore for messages addressed to any of its held keys.
type Client struct {
	blocks     blockstore.Store
	messages   *MessageStore
	identities []*Identity
	channels   []Channel
}

// New creates a Client. All identity and channel keys are tried on every block.
func New(blocks blockstore.Store, messages *MessageStore, identities []*Identity, channels []Channel) *Client {
	return &Client{blocks: blocks, messages: messages, identities: identities, channels: channels}
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
			mp, identityName, ok := c.tryAllKeys(payload)
			if !ok {
				continue
			}
			mp.DecryptedBy = identityName

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

// tryAllKeys attempts decryption with each held private key and channel key.
// Returns the MessagePayload, the identity name that decrypted it (empty for
// channel messages), and true on the first success.
func (c *Client) tryAllKeys(payload blockstore.Payload) (MessagePayload, string, bool) {
	for _, id := range c.identities {
		if mp, err := tryDecrypt(id.SignKey, payload); err == nil {
			return mp, id.Name, true
		}
	}
	for _, ch := range c.channels {
		if mp, err := tryDecryptChannel(ch.Key, payload); err == nil {
			mp.Channel = ch.Name
			return mp, "", true
		}
	}
	return MessagePayload{}, "", false
}

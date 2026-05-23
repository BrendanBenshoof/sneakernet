package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// Client talks to a relay Server over HTTP.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a relay Client targeting baseURL (no trailing slash).
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Get fetches a block by its ID.
// Returns blockstore.ErrNotFound if the relay does not have the block.
func (c *Client) Get(ctx context.Context, id blockstore.ID) (blockstore.Stamp, blockstore.Payload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/block/"+hex.EncodeToString(id[:]), nil)
	if err != nil {
		return blockstore.Stamp{}, blockstore.Payload{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return blockstore.Stamp{}, blockstore.Payload{}, fmt.Errorf("relay get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return blockstore.Stamp{}, blockstore.Payload{}, blockstore.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return blockstore.Stamp{}, blockstore.Payload{}, fmt.Errorf("relay get: status %d", resp.StatusCode)
	}

	const blockSize = blockstore.StampSize + blockstore.PayloadSize
	body, err := io.ReadAll(io.LimitReader(resp.Body, blockSize))
	if err != nil {
		return blockstore.Stamp{}, blockstore.Payload{}, fmt.Errorf("relay get: read: %w", err)
	}
	if len(body) != blockSize {
		return blockstore.Stamp{}, blockstore.Payload{}, fmt.Errorf("relay get: short response (%d bytes)", len(body))
	}

	var stamp blockstore.Stamp
	var payload blockstore.Payload
	copy(stamp[:], body[:blockstore.StampSize])
	copy(payload[:], body[blockstore.StampSize:])
	return stamp, payload, nil
}

// Put uploads a block to the relay. Returns the block ID assigned by the relay.
// Returns an error if the relay rejects the block (e.g. insufficient PoW).
func (c *Client) Put(ctx context.Context, stamp blockstore.Stamp, payload blockstore.Payload) (blockstore.ID, error) {
	body := make([]byte, blockstore.StampSize+blockstore.PayloadSize)
	copy(body[:blockstore.StampSize], stamp[:])
	copy(body[blockstore.StampSize:], payload[:])

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/block", bytes.NewReader(body))
	if err != nil {
		return blockstore.ID{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return blockstore.ID{}, fmt.Errorf("relay put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody)
		return blockstore.ID{}, fmt.Errorf("relay put: status %d: %s", resp.StatusCode, errBody.Error)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return blockstore.ID{}, fmt.Errorf("relay put: decode response: %w", err)
	}
	idBytes, err := hex.DecodeString(result.ID)
	if err != nil || len(idBytes) != blockstore.IDSize {
		return blockstore.ID{}, fmt.Errorf("relay put: invalid id in response")
	}
	var id blockstore.ID
	copy(id[:], idBytes)
	return id, nil
}

// Delta queries the relay for block IDs that are not represented in bloom,
// filtered to blocks with work_factor >= powFloor and created after since.
// Use BloomOfStore to build a filter of your current local blocks.
func (c *Client) Delta(ctx context.Context, bloom *Bloom, powFloor int, since time.Time) ([]blockstore.ID, error) {
	reqBody := map[string]any{
		"bloom":     base64.StdEncoding.EncodeToString(bloom.Bytes()),
		"pow_floor": powFloor,
		"since":     since.Unix(),
	}
	buf, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/delta", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay delta: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay delta: status %d", resp.StatusCode)
	}

	var result struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("relay delta: decode: %w", err)
	}

	ids := make([]blockstore.ID, 0, len(result.IDs))
	for _, hexID := range result.IDs {
		b, err := hex.DecodeString(hexID)
		if err != nil || len(b) != blockstore.IDSize {
			return nil, fmt.Errorf("relay delta: invalid id %q", hexID)
		}
		var id blockstore.ID
		copy(id[:], b)
		ids = append(ids, id)
	}
	return ids, nil
}

// GetPowLimit queries the relay for its current minimum proof-of-work requirement.
func (c *Client) GetPowLimit(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/pow-limit", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("relay pow-limit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("relay pow-limit: status %d", resp.StatusCode)
	}

	var result struct {
		PowFloor int `json:"pow_floor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("relay pow-limit: decode: %w", err)
	}
	return result.PowFloor, nil
}

// Pull fetches all blocks from the relay that are not in localStore.
// It builds a bloom filter of local blocks, calls Delta, then fetches and
// stores each missing block. Returns the count of newly stored blocks.
func (c *Client) Pull(ctx context.Context, localStore blockstore.Store, powFloor int, since time.Time) (int, error) {
	bloom, err := BloomOfStore(localStore)
	if err != nil {
		return 0, fmt.Errorf("relay pull: build bloom: %w", err)
	}

	missing, err := c.Delta(ctx, bloom, powFloor, since)
	if err != nil {
		return 0, fmt.Errorf("relay pull: delta: %w", err)
	}

	var stored int
	for _, id := range missing {
		if err := ctx.Err(); err != nil {
			return stored, err
		}
		// Skip blocks we actually have (bloom may false-positive in reverse).
		if ok, _ := localStore.Has(id); ok {
			continue
		}
		stamp, payload, err := c.Get(ctx, id)
		if err != nil {
			continue // relay may have pruned it between delta and get
		}
		if _, err := localStore.Put(stamp, payload); err != nil {
			return stored, fmt.Errorf("relay pull: store block: %w", err)
		}
		stored++
	}
	return stored, nil
}

// Push uploads all local blocks meeting powFloor to the relay.
// Blocks the relay already holds are silently accepted by the relay's
// INSERT OR REPLACE, so this is safe to call repeatedly.
// Returns the count of blocks successfully uploaded.
func (c *Client) Push(ctx context.Context, localStore blockstore.Store, powFloor int, since time.Time) (int, error) {
	relayPow, err := c.GetPowLimit(ctx)
	if err != nil {
		return 0, fmt.Errorf("relay push: %w", err)
	}
	if relayPow > powFloor {
		powFloor = relayPow
	}

	var uploaded int
	pageToken := ""
	for {
		if err := ctx.Err(); err != nil {
			return uploaded, err
		}
		next, refs, err := localStore.ListBlocks(pageToken, 100, powFloor, since)
		if err != nil {
			return uploaded, fmt.Errorf("relay push: list: %w", err)
		}
		for _, ref := range refs {
			stamp, payload, err := localStore.Get(ref.ID)
			if err != nil {
				continue // expired between list and get
			}
			if _, err := c.Put(ctx, stamp, payload); err != nil {
				continue // relay rejected (PoW race, etc.) — not fatal
			}
			uploaded++
		}
		if next == "" {
			break
		}
		pageToken = next
	}
	return uploaded, nil
}

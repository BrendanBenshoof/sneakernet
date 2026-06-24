// Package bluetooth implements the Sneakernet Bluetooth Block Exchange
// Protocol (SBBEP) — a symmetric, binary-framed block-sync session that runs
// over any io.ReadWriter (Bluetooth Classic RFCOMM on Android, io.Pipe in
// tests, etc.).
//
// Both endpoints call Run concurrently after the transport connection is
// established. Neither side is "client" or "server": each sends its full
// bloom filter, then streams blocks the other side is missing, then signals
// DONE. The session completes when both DONE frames have been exchanged.
package bluetooth

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/brendanbenshoof/sneakernet/blockstore"
	"github.com/brendanbenshoof/sneakernet/transport/relay"
)

// ServiceUUID is the Bluetooth SDP / BLE service UUID for sneakernet.
// Android uses this for both the RFCOMM server socket and BLE advertising.
const ServiceUUID = "b533e7a1-4c6d-4f89-aeb2-73c97a8d1e40"

// Frame type bytes.
const (
	frameBloom  byte = 0x01 // 8192-byte bloom filter of local blocks
	frameBlock  byte = 0x02 // single block: stamp (4 bytes) + payload (4096 bytes)
	frameDone   byte = 0x03 // sender has no more blocks to send
	framePeers  byte = 0x04 // JSON array of known internet relay URLs; sent after DONE
)

// maxGossipPeers caps how many relay URLs are shared per session.
const maxGossipPeers = 20

const (
	maxFrameLen    = 1 << 20                                       // 1 MiB sanity cap
	blockFrameSize = blockstore.StampSize + blockstore.PayloadSize // 4100 bytes
)

// Run executes a complete block-exchange session over rw with store, then
// exchanges known internet relay URLs with the peer (best-effort; failure
// does not abort the session). knownPeers is the caller's list of active
// relay URLs to share; up to maxGossipPeers are sent.
//
// Returns the peer's relay URLs so the caller can add them to its peer list.
// Blocks received from the peer are stored with TagBluetooth.
func Run(ctx context.Context, rw io.ReadWriter, store blockstore.Store, knownPeers []string) ([]string, error) {
	// peerBloomCh carries the remote bloom filter from the receiver goroutine
	// to the sender goroutine so the sender knows which blocks to skip.
	peerBloomCh := make(chan *relay.Bloom, 1)

	var sendErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = runSend(ctx, rw, store, peerBloomCh)
	}()

	recvErr := runRecv(rw, store, peerBloomCh)
	wg.Wait()

	if recvErr != nil {
		return nil, recvErr
	}
	if sendErr != nil {
		return nil, sendErr
	}

	// Block exchange complete. Share relay peer lists (best-effort).
	return exchangePeers(rw, knownPeers), nil
}

// exchangePeers sends knownPeers as a JSON array and reads the peer's list.
// Both sides write and read simultaneously. Non-fatal: returns nil on any error.
func exchangePeers(rw io.ReadWriter, knownPeers []string) []string {
	if len(knownPeers) > maxGossipPeers {
		knownPeers = knownPeers[:maxGossipPeers]
	}
	data, _ := json.Marshal(knownPeers)

	writeCh := make(chan error, 1)
	go func() {
		writeCh <- writeFrame(rw, framePeers, data)
	}()

	ftype, peerData, readErr := readFrame(rw)
	if <-writeCh != nil || readErr != nil || ftype != framePeers {
		return nil
	}

	var peers []string
	json.Unmarshal(peerData, &peers) //nolint:errcheck
	return peers
}

// runSend builds the local bloom, sends it, waits for the peer's bloom via
// peerBloomCh, then streams every block the peer is missing, then sends DONE.
func runSend(ctx context.Context, w io.Writer, store blockstore.Store, peerBloomCh <-chan *relay.Bloom) error {
	bloom, err := relay.BloomOfStore(store)
	if err != nil {
		return fmt.Errorf("bluetooth send: build bloom: %w", err)
	}
	if err := writeFrame(w, frameBloom, bloom.Bytes()); err != nil {
		return fmt.Errorf("bluetooth send: write bloom: %w", err)
	}

	var peerBloom *relay.Bloom
	select {
	case <-ctx.Done():
		_ = writeFrame(w, frameDone, nil)
		return ctx.Err()
	case pb, ok := <-peerBloomCh:
		if !ok {
			// receiver closed channel without delivering a bloom (recv error)
			return nil
		}
		peerBloom = pb
	}

	pageToken := ""
	for {
		if ctx.Err() != nil {
			break
		}
		next, refs, err := store.ListBlocks(pageToken, 100, 0, time.Time{})
		if err != nil {
			break
		}
		for _, ref := range refs {
			if peerBloom.Has(ref.ID, ref.WorkFactor) {
				continue
			}
			stamp, payload, err := store.Get(ref.ID)
			if err != nil {
				continue // expired between list and get
			}
			frame := make([]byte, blockFrameSize)
			copy(frame[:blockstore.StampSize], stamp[:])
			copy(frame[blockstore.StampSize:], payload[:])
			if err := writeFrame(w, frameBlock, frame); err != nil {
				return fmt.Errorf("bluetooth send: write block: %w", err)
			}
		}
		if next == "" {
			break
		}
		pageToken = next
	}

	return writeFrame(w, frameDone, nil)
}

// runRecv reads frames from r: delivers the BLOOM frame to peerBloomCh, stores
// incoming BLOCK frames, and returns nil when DONE is received.
func runRecv(r io.Reader, store blockstore.Store, peerBloomCh chan<- *relay.Bloom) error {
	bloomDelivered := false
	for {
		ftype, data, err := readFrame(r)
		if err != nil {
			if !bloomDelivered {
				close(peerBloomCh)
			}
			return err
		}
		switch ftype {
		case frameBloom:
			pb, err := relay.BloomFromBytes(data)
			if err != nil {
				close(peerBloomCh)
				return fmt.Errorf("bluetooth recv: parse bloom: %w", err)
			}
			bloomDelivered = true
			peerBloomCh <- pb
		case frameBlock:
			if len(data) != blockFrameSize {
				return fmt.Errorf("bluetooth recv: bad block frame size %d", len(data))
			}
			var stamp blockstore.Stamp
			var payload blockstore.Payload
			copy(stamp[:], data[:blockstore.StampSize])
			copy(payload[:], data[blockstore.StampSize:])
			_, _ = store.Put(stamp, payload, blockstore.TagBluetooth)
		case frameDone:
			return nil
		default:
			return fmt.Errorf("bluetooth recv: unknown frame type 0x%02x", ftype)
		}
	}
}

// writeFrame writes [type: 1][length: 4 BE][data: length] to w.
func writeFrame(w io.Writer, ftype byte, data []byte) error {
	var header [5]byte
	header[0] = ftype
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := w.Write(data)
		return err
	}
	return nil
}

// readFrame reads one complete frame from r and returns its type and payload.
func readFrame(r io.Reader) (ftype byte, data []byte, err error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	ftype = header[0]
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxFrameLen {
		return 0, nil, fmt.Errorf("bluetooth: frame too large: %d bytes", length)
	}
	if length == 0 {
		return ftype, nil, nil
	}
	data = make([]byte, length)
	_, err = io.ReadFull(r, data)
	return ftype, data, err
}

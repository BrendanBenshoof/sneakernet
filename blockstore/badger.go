package blockstore

import (
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

// MedianWorkFactor returns the in-memory median work_factor, updated by the
// background updater every medianCacheTTL after each run completes.
func (s *BadgerStore) MedianWorkFactor() (int, error) {
	return s.medianWF, nil
}

// RefreshMedian forces an immediate synchronous recompute of the cached median.
// Intended for use after bulk loads and in tests.
func (s *BadgerStore) RefreshMedian() error {
	wf, err := s.computeMedianWorkFactor()
	if err != nil {
		return err
	}
	s.medianWF = wf
	return nil
}

func (s *BadgerStore) runMedianUpdater() {
	for {
		if wf, err := s.computeMedianWorkFactor(); err == nil {
			s.medianWF = wf
		}
		select {
		case <-s.done:
			return
		case <-time.After(medianCacheTTL):
		}
	}
}

func (s *BadgerStore) computeMedianWorkFactor() (int, error) {
	var wfs []int
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{travPrefix}
		opts.PrefetchValues = true
		opts.PrefetchSize = 256
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if err := it.Item().Value(func(val []byte) error {
				if len(val) >= 4 {
					wfs = append(wfs, int(binary.BigEndian.Uint32(val)))
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("blockstore: median work factor: %w", err)
	}
	if len(wfs) == 0 {
		return 0, nil
	}
	sort.Ints(wfs)
	return wfs[len(wfs)/2], nil
}

const (
	blockPrefix = byte('b')
	travPrefix  = byte('t')
	tombPrefix  = byte('x')

	// blockValHeaderSize: stamp[4] + wf[4] + created_at[8] + tag[1] = 17 bytes.
	blockValHeaderSize = StampSize + 4 + 8 + 1

	evictBatch      = int64(10)           // extra blocks to evict beyond the immediate minimum
	tombstoneTTL    = 14 * 24 * time.Hour // how long eviction tombstones block re-acceptance
	medianCacheTTL  = 5 * time.Minute     // how often MedianWorkFactor recomputes
)

// BadgerStore is a BadgerDB-backed implementation of Store.
// Key layout:
//
//	block key:     'b' | id[32]                → stamp[4] | wf[4] | created_at[8] | tag[1] | payload[4096]
//	trav  key:     't' | created_at[8] | id[32] → wf[4] | tag[1]
//	tombstone key: 'x' | id[32]                → (empty)                                                    (TTL = tombstoneTTL)
type BadgerStore struct {
	db           *badger.DB
	storageLimit int64         // 0 = no limit
	reservations map[Tag]int64 // reserved bytes per tag; absent tags have reservation 0

	medianWF int
	done     chan struct{}
}

// OpenBadger opens (or creates) a BadgerDB blockstore at dir.
func OpenBadger(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("blockstore: badger open: %w", err)
	}
	s := &BadgerStore{db: db, done: make(chan struct{})}
	go s.runMedianUpdater()
	return s, nil
}

// WithStorageLimit sets the maximum total storage in bytes. When Put pushes
// usage over this threshold, the least-valuable blocks are evicted to make
// room. A limit of 0 disables enforcement.
func (s *BadgerStore) WithStorageLimit(bytes int64) *BadgerStore {
	s.storageLimit = bytes
	return s
}

// WithReservations configures per-tag storage guarantees. During eviction the
// tag with the largest (usage − reservation) is targeted first. Tags absent
// from the map have an implicit reservation of 0.
func (s *BadgerStore) WithReservations(r map[Tag]int64) *BadgerStore {
	s.reservations = r
	return s
}

func (s *BadgerStore) blockKey(id ID) []byte {
	key := make([]byte, 1+IDSize)
	key[0] = blockPrefix
	copy(key[1:], id[:])
	return key
}

func (s *BadgerStore) travKey(createdAt int64, id ID) []byte {
	key := make([]byte, 1+8+IDSize)
	key[0] = travPrefix
	if createdAt < 0 {
		createdAt = 0
	}
	binary.BigEndian.PutUint64(key[1:9], uint64(createdAt))
	copy(key[9:], id[:])
	return key
}

func (s *BadgerStore) tombKey(id ID) []byte {
	key := make([]byte, 1+IDSize)
	key[0] = tombPrefix
	copy(key[1:], id[:])
	return key
}

func encodeBlockVal(stamp Stamp, wf int, createdAt int64, tag Tag, payload Payload) []byte {
	val := make([]byte, blockValHeaderSize+PayloadSize)
	copy(val[:StampSize], stamp[:])
	binary.BigEndian.PutUint32(val[StampSize:StampSize+4], uint32(wf))
	binary.BigEndian.PutUint64(val[StampSize+4:StampSize+12], uint64(createdAt))
	val[StampSize+12] = byte(tag)
	copy(val[blockValHeaderSize:], payload[:])
	return val
}

func (s *BadgerStore) Put(stamp Stamp, payload Payload, tag Tag) (ID, error) {
	id := ComputeID(payload)
	wf := WorkFactor(stamp, payload)
	now := time.Now()

	err := s.db.Update(func(txn *badger.Txn) error {
		// Don't re-accept tombstoned blocks.
		if _, err := txn.Get(s.tombKey(id)); err == nil {
			return nil
		} else if err != badger.ErrKeyNotFound {
			return err
		}

		bKey := s.blockKey(id)
		createdAt := now.Unix()

		item, err := txn.Get(bKey)
		if err == nil {
			var skip bool
			if valErr := item.Value(func(existing []byte) error {
				if len(existing) >= StampSize+4+8 {
					existingWF := int(binary.BigEndian.Uint32(existing[StampSize : StampSize+4]))
					if existingWF >= wf {
						skip = true
						return nil
					}
					// Keep original created_at so trav key is stable.
					createdAt = int64(binary.BigEndian.Uint64(existing[StampSize+4 : StampSize+12]))
				}
				return nil
			}); valErr != nil {
				return valErr
			}
			if skip {
				return nil
			}
		} else if err != badger.ErrKeyNotFound {
			return err
		}

		bEntry := badger.NewEntry(bKey, encodeBlockVal(stamp, wf, createdAt, tag, payload))
		if err := txn.SetEntry(bEntry); err != nil {
			return err
		}
		travVal := make([]byte, 5)
		binary.BigEndian.PutUint32(travVal, uint32(wf))
		travVal[4] = byte(tag)
		tEntry := badger.NewEntry(s.travKey(createdAt, id), travVal)
		return txn.SetEntry(tEntry)
	})
	if err != nil {
		return ID{}, fmt.Errorf("blockstore: put: %w", err)
	}

	// Enforce storage limit after storing; best-effort (ignore eviction error).
	if s.storageLimit > 0 {
		lsm, vlog := s.db.Size()
		if lsm+vlog > s.storageLimit {
			needed := (lsm+vlog-s.storageLimit)/int64(blockValHeaderSize+PayloadSize) + evictBatch
			if needed < 1 {
				needed = 1
			}
			s.Evict(int(needed)) //nolint:errcheck
		}
	}

	return id, nil
}

func (s *BadgerStore) GetWorkFactor(id ID) (int, error) {
	var wf int
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(s.blockKey(id))
		if err == badger.ErrKeyNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) < StampSize+4 {
				return fmt.Errorf("blockstore: corrupt block value")
			}
			wf = int(binary.BigEndian.Uint32(val[StampSize : StampSize+4]))
			return nil
		})
	})
	return wf, err
}

func (s *BadgerStore) Get(id ID) (Stamp, Payload, error) {
	var stamp Stamp
	var payload Payload
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(s.blockKey(id))
		if err == badger.ErrKeyNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) < blockValHeaderSize+PayloadSize {
				return fmt.Errorf("blockstore: corrupt block value for %x", id)
			}
			copy(stamp[:], val[:StampSize])
			copy(payload[:], val[blockValHeaderSize:blockValHeaderSize+PayloadSize])
			return nil
		})
	})
	if err != nil {
		return Stamp{}, Payload{}, err
	}
	return stamp, payload, nil
}

// Has returns true if the block is present OR if a tombstone exists for it.
// A tombstone means the block was evicted and will not be re-accepted, so
// callers should treat it as "already seen".
func (s *BadgerStore) Has(id ID) (bool, error) {
	err := s.db.View(func(txn *badger.Txn) error {
		if _, err := txn.Get(s.blockKey(id)); err == nil {
			return nil
		} else if err != badger.ErrKeyNotFound {
			return err
		}
		_, err := txn.Get(s.tombKey(id))
		return err
	})
	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("blockstore: has: %w", err)
	}
	return true, nil
}

func (s *BadgerStore) ListIDs() ([]ID, error) {
	var ids []ID
	prefix := []byte{blockPrefix}
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			if len(key) != 1+IDSize {
				continue
			}
			var id ID
			copy(id[:], key[1:])
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("blockstore: listids: %w", err)
	}
	return ids, nil
}

func (s *BadgerStore) ListBlocks(pageToken string, limit int, powFloor int, since time.Time) (string, []BlockRef, error) {
	sinceUnix := since.Unix()
	if sinceUnix < 0 {
		sinceUnix = 0
	}

	var seekCreatedAt int64
	var seekID ID
	hasCursor := false
	if pageToken != "" {
		cur, err := decodeCursor(pageToken)
		if err != nil {
			return "", nil, err
		}
		seekCreatedAt = cur.createdAt
		seekID = cur.id
		hasCursor = true
	} else {
		seekCreatedAt = sinceUnix
	}

	var refs []BlockRef
	var last cursor

	prefix := []byte{travPrefix}
	seekKey := s.travKey(seekCreatedAt, seekID)

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Seek(seekKey)

		// When paginating, skip past the cursor entry itself.
		if hasCursor && it.Valid() {
			key := it.Item().Key()
			if len(key) == 1+8+IDSize {
				ca := int64(binary.BigEndian.Uint64(key[1:9]))
				var cid ID
				copy(cid[:], key[9:])
				if ca == seekCreatedAt && cid == seekID {
					it.Next()
				}
			}
		}

		for ; it.Valid() && len(refs) < limit; it.Next() {
			key := it.Item().Key()
			if len(key) != 1+8+IDSize {
				continue
			}
			createdAt := int64(binary.BigEndian.Uint64(key[1:9]))
			if createdAt < sinceUnix {
				continue
			}
			var id ID
			copy(id[:], key[9:])

			var wf int
			var tag Tag
			if err := it.Item().Value(func(val []byte) error {
				if len(val) >= 4 {
					wf = int(binary.BigEndian.Uint32(val))
				}
				if len(val) >= 5 {
					tag = Tag(val[4])
				}
				return nil
			}); err != nil {
				return err
			}
			if wf < powFloor {
				continue
			}

			refs = append(refs, BlockRef{ID: id, WorkFactor: wf, Tag: tag})
			last.createdAt = createdAt
			last.id = id
		}
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("blockstore: listblocks: %w", err)
	}

	var nextToken string
	if len(refs) == limit {
		nextToken = encodeCursor(last)
	}
	return nextToken, refs, nil
}

// Prune triggers value log GC to reclaim disk space from expired blocks.
// BadgerDB expires keys automatically; this call reclaims the disk space.
// Returns 0 for count since BadgerDB does not expose a pruned-entry count.
func (s *BadgerStore) Prune() (int, error) {
	err := s.db.RunValueLogGC(0.5)
	if err == badger.ErrNoRewrite {
		return 0, nil
	}
	return 0, err
}

type evictCandidate struct {
	id        ID
	createdAt int64
	wf        int
	tag       Tag
}

// Evict removes up to n blocks, choosing the tag most over its configured
// reservation at each step, then picking the block with the soonest logical
// expiry (createdAt + TTLFromWorkFactor(wf)) within that tag — lower-PoW
// blocks are evicted first. A tombstone with tombstoneTTL is written for each
// evicted ID so it is not re-accepted within that window.
func (s *BadgerStore) Evict(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}

	// Collect all live blocks with their tag and expiry time.
	var all []evictCandidate
	if err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{blockPrefix}
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if len(key) != 1+IDSize {
				continue
			}
			var id ID
			copy(id[:], key[1:])
			var createdAt int64
			var wf int
			var tag Tag
			if err := item.Value(func(val []byte) error {
				if len(val) >= blockValHeaderSize {
					wf = int(binary.BigEndian.Uint32(val[StampSize : StampSize+4]))
					createdAt = int64(binary.BigEndian.Uint64(val[StampSize+4 : StampSize+12]))
					tag = Tag(val[StampSize+12])
				}
				return nil
			}); err != nil {
				return err
			}
			all = append(all, evictCandidate{
				id: id, createdAt: createdAt, wf: wf, tag: tag,
			})
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("blockstore: evict: scan: %w", err)
	}

	// Build per-tag candidate lists sorted soonest-expiring first.
	const blockSize = int64(blockValHeaderSize + PayloadSize)
	perTag := make(map[Tag][]evictCandidate)
	tagUsage := make(map[Tag]int64)
	for _, c := range all {
		perTag[c.tag] = append(perTag[c.tag], c)
		tagUsage[c.tag] += blockSize
	}
	logicalExpiry := func(c evictCandidate) int64 {
		return c.createdAt + int64(TTLFromWorkFactor(c.wf)/time.Second)
	}
	for t := range perTag {
		sort.Slice(perTag[t], func(i, j int) bool {
			return logicalExpiry(perTag[t][i]) < logicalExpiry(perTag[t][j])
		})
	}

	var evicted int
	for evicted < n {
		// Pick the non-empty tag furthest above its reservation.
		var target Tag
		var maxOver int64 = -1 << 62
		hasTarget := false
		for t, usage := range tagUsage {
			if len(perTag[t]) == 0 {
				continue
			}
			over := usage - s.reservations[t]
			if !hasTarget || over > maxOver {
				maxOver = over
				target = t
				hasTarget = true
			}
		}
		if !hasTarget {
			break
		}

		c := perTag[target][0]
		perTag[target] = perTag[target][1:]
		tagUsage[target] -= blockSize

		if err := s.db.Update(func(txn *badger.Txn) error {
			if err := txn.Delete(s.blockKey(c.id)); err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			if err := txn.Delete(s.travKey(c.createdAt, c.id)); err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			tomb := badger.NewEntry(s.tombKey(c.id), []byte{}).WithTTL(tombstoneTTL)
			return txn.SetEntry(tomb)
		}); err != nil {
			return evicted, fmt.Errorf("blockstore: evict: %w", err)
		}
		evicted++
	}
	return evicted, nil
}

func (s *BadgerStore) Close() error {
	close(s.done)
	return s.db.Close()
}

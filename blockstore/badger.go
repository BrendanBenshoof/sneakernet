package blockstore

import (
	"encoding/binary"
	"fmt"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

const (
	blockPrefix = byte('b')
	travPrefix  = byte('t')
)

// BadgerStore is a BadgerDB-backed implementation of Store.
// Key layout:
//   block key: 'b' | id[32]                          → stamp[4] | wf[4] | created_at[8] | payload[4096]  (TTL set)
//   trav  key: 't' | created_at[8] | id[32]          → wf[4]                                             (TTL set)
type BadgerStore struct {
	db *badger.DB
}

// OpenBadger opens (or creates) a BadgerDB blockstore at dir.
func OpenBadger(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("blockstore: badger open: %w", err)
	}
	return &BadgerStore{db: db}, nil
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

func encodeBlockVal(stamp Stamp, wf int, createdAt int64, payload Payload) []byte {
	val := make([]byte, StampSize+4+8+PayloadSize)
	copy(val[:StampSize], stamp[:])
	binary.BigEndian.PutUint32(val[StampSize:StampSize+4], uint32(wf))
	binary.BigEndian.PutUint64(val[StampSize+4:StampSize+12], uint64(createdAt))
	copy(val[StampSize+12:], payload[:])
	return val
}

func (s *BadgerStore) Put(stamp Stamp, payload Payload) (ID, error) {
	id := ComputeID(payload)
	wf := WorkFactor(stamp, payload)
	now := time.Now()
	ttl := TTLFromWorkFactor(wf)

	err := s.db.Update(func(txn *badger.Txn) error {
		bKey := s.blockKey(id)
		createdAt := now.Unix()

		item, err := txn.Get(bKey)
		if err == nil {
			// Block exists; keep only if new wf is higher.
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

		bEntry := badger.NewEntry(bKey, encodeBlockVal(stamp, wf, createdAt, payload)).WithTTL(ttl)
		if err := txn.SetEntry(bEntry); err != nil {
			return err
		}
		travVal := make([]byte, 4)
		binary.BigEndian.PutUint32(travVal, uint32(wf))
		tEntry := badger.NewEntry(s.travKey(createdAt, id), travVal).WithTTL(ttl)
		return txn.SetEntry(tEntry)
	})
	if err != nil {
		return ID{}, fmt.Errorf("blockstore: put: %w", err)
	}
	return id, nil
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
			if len(val) < StampSize+4+8+PayloadSize {
				return fmt.Errorf("blockstore: corrupt block value for %x", id)
			}
			copy(stamp[:], val[:StampSize])
			copy(payload[:], val[StampSize+12:StampSize+12+PayloadSize])
			return nil
		})
	})
	if err != nil {
		return Stamp{}, Payload{}, err
	}
	return stamp, payload, nil
}

func (s *BadgerStore) Has(id ID) (bool, error) {
	err := s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(s.blockKey(id))
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
			if err := it.Item().Value(func(val []byte) error {
				if len(val) >= 4 {
					wf = int(binary.BigEndian.Uint32(val))
				}
				return nil
			}); err != nil {
				return err
			}
			if wf < powFloor {
				continue
			}

			refs = append(refs, BlockRef{ID: id, WorkFactor: wf})
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

func (s *BadgerStore) Close() error {
	return s.db.Close()
}

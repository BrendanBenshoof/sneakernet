package blockstore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// flatHeaderSize is the fixed header preceding the payload in each block file.
//
//	stamp[4] | work_factor uint32[4] | created_at int64[8] | expires_at int64[8]
//
// expires_at is the logical TTL deadline (createdAt + TTLFromWorkFactor(wf)) and
// is written for eviction-ordering purposes only — it is not an acceptance gate.
const flatHeaderSize = StampSize + 4 + 8 + 8 // 24 bytes

// FlatFileStore is a filesystem-backed implementation of Store intended for
// mass storage and human-inspectable backups.
//
// Each block is stored as a single file:
//
//	{root}/{id[0]:02x}/{id[1]:02x}/{hex(id)}
//
// Two levels of directory sharding (65536 leaf dirs) keep individual
// directories manageable up to ~1 TB (≈230 M blocks at 4 KB each).
//
// Blocks are retained as long as there is physical allocation. When Put
// exceeds the storage limit, Evict is called to free space by removing the
// blocks with the lowest logical priority (soonest logical expiry first).
type FlatFileStore struct {
	root         string
	storageLimit int64 // 0 = no limit
}

// OpenFlatFile opens (or creates) a flat-file blockstore rooted at dir.
func OpenFlatFile(dir string) (*FlatFileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("blockstore: flatfile: mkdir: %w", err)
	}
	return &FlatFileStore{root: dir}, nil
}

// WithStorageLimit sets the maximum total storage in bytes. When Put would
// push usage over this threshold, the lowest-priority blocks are evicted first.
// A limit of 0 disables enforcement.
func (s *FlatFileStore) WithStorageLimit(bytes int64) *FlatFileStore {
	s.storageLimit = bytes
	return s
}

func (s *FlatFileStore) blockPath(id ID) string {
	h := hex.EncodeToString(id[:])
	return filepath.Join(s.root, h[:2], h[2:4], h)
}

const flatFileSize = int64(flatHeaderSize + PayloadSize)

func (s *FlatFileStore) diskUsage() (int64, error) {
	var count int64
	err := filepath.WalkDir(s.root, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if len(d.Name()) == 2*IDSize {
			count++
		}
		return nil
	})
	return count * flatFileSize, err
}

func (s *FlatFileStore) Put(stamp Stamp, payload Payload, _ Tag) (ID, error) {
	id := ComputeID(payload)
	wf := WorkFactor(stamp, payload)
	now := time.Now()
	expiresAt := now.Add(TTLFromWorkFactor(wf))

	path := s.blockPath(id)

	// If a file already exists with equal or higher work factor, keep it.
	if f, err := os.Open(path); err == nil {
		var hdr [flatHeaderSize]byte
		_, readErr := io.ReadFull(f, hdr[:])
		f.Close()
		if readErr == nil {
			existingWF := int(binary.BigEndian.Uint32(hdr[StampSize : StampSize+4]))
			if existingWF >= wf {
				return id, nil
			}
		}
	}

	// Enforce storage limit; evict lowest-priority blocks to make room.
	if s.storageLimit > 0 {
		if usage, err := s.diskUsage(); err == nil && usage >= s.storageLimit {
			needed := (usage-s.storageLimit)/flatFileSize + 10 + 1
			s.Evict(int(needed)) //nolint:errcheck
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ID{}, fmt.Errorf("blockstore: flatfile: mkdir: %w", err)
	}

	var buf [flatHeaderSize + PayloadSize]byte
	copy(buf[:StampSize], stamp[:])
	binary.BigEndian.PutUint32(buf[StampSize:StampSize+4], uint32(wf))
	binary.BigEndian.PutUint64(buf[StampSize+4:StampSize+12], uint64(now.Unix()))
	binary.BigEndian.PutUint64(buf[StampSize+12:StampSize+20], uint64(expiresAt.Unix()))
	copy(buf[flatHeaderSize:], payload[:])

	// Atomic write via a sibling temp file then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf[:], 0o644); err != nil {
		return ID{}, fmt.Errorf("blockstore: flatfile: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return ID{}, fmt.Errorf("blockstore: flatfile: rename: %w", err)
	}
	return id, nil
}

func (s *FlatFileStore) readHeader(path string) (stamp Stamp, wf int, createdAt, expiresAt int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var hdr [flatHeaderSize]byte
	if _, err = io.ReadFull(f, hdr[:]); err != nil {
		err = fmt.Errorf("blockstore: flatfile: read header: %w", err)
		return
	}
	copy(stamp[:], hdr[:StampSize])
	wf = int(binary.BigEndian.Uint32(hdr[StampSize : StampSize+4]))
	createdAt = int64(binary.BigEndian.Uint64(hdr[StampSize+4 : StampSize+12]))
	expiresAt = int64(binary.BigEndian.Uint64(hdr[StampSize+12 : StampSize+20]))
	return
}

func (s *FlatFileStore) Get(id ID) (Stamp, Payload, error) {
	path := s.blockPath(id)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Stamp{}, Payload{}, ErrNotFound
	}
	if err != nil {
		return Stamp{}, Payload{}, fmt.Errorf("blockstore: flatfile: get: %w", err)
	}
	defer f.Close()

	var buf [flatHeaderSize + PayloadSize]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return Stamp{}, Payload{}, fmt.Errorf("blockstore: flatfile: get: %w", err)
	}
	var stamp Stamp
	var payload Payload
	copy(stamp[:], buf[:StampSize])
	copy(payload[:], buf[flatHeaderSize:])
	return stamp, payload, nil
}

func (s *FlatFileStore) GetWorkFactor(id ID) (int, error) {
	_, wf, _, _, err := s.readHeader(s.blockPath(id))
	if os.IsNotExist(err) {
		return 0, ErrNotFound
	}
	return wf, err
}

func (s *FlatFileStore) Has(id ID) (bool, error) {
	_, _, _, _, err := s.readHeader(s.blockPath(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *FlatFileStore) ListIDs() ([]ID, error) {
	var ids []ID
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		idBytes, decErr := hex.DecodeString(d.Name())
		if decErr != nil || len(idBytes) != IDSize {
			return nil
		}
		if _, err := os.Stat(path); err != nil {
			return nil
		}
		var id ID
		copy(id[:], idBytes)
		ids = append(ids, id)
		return nil
	})
	return ids, err
}

type flatEntry struct {
	id        ID
	wf        int
	createdAt int64
}

func (s *FlatFileStore) ListBlocks(pageToken string, limit int, powFloor int, since time.Time) (string, []BlockRef, error) {
	sinceUnix := since.Unix()

	var cur cursor
	hasCursor := false
	if pageToken != "" {
		var err error
		cur, err = decodeCursor(pageToken)
		if err != nil {
			return "", nil, err
		}
		hasCursor = true
	}

	var entries []flatEntry
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		idBytes, decErr := hex.DecodeString(d.Name())
		if decErr != nil || len(idBytes) != IDSize {
			return nil
		}
		_, wf, createdAt, _, hdrErr := s.readHeader(path)
		if hdrErr != nil || wf < powFloor || createdAt < sinceUnix {
			return nil
		}
		var id ID
		copy(id[:], idBytes)
		entries = append(entries, flatEntry{id: id, wf: wf, createdAt: createdAt})
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("blockstore: flatfile: listblocks: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].createdAt != entries[j].createdAt {
			return entries[i].createdAt < entries[j].createdAt
		}
		return bytes.Compare(entries[i].id[:], entries[j].id[:]) < 0
	})

	var refs []BlockRef
	var last cursor
	for _, e := range entries {
		if hasCursor {
			if e.createdAt < cur.createdAt {
				continue
			}
			if e.createdAt == cur.createdAt && bytes.Compare(e.id[:], cur.id[:]) <= 0 {
				continue
			}
		}
		refs = append(refs, BlockRef{ID: e.id, WorkFactor: e.wf})
		last.createdAt = e.createdAt
		last.id = e.id
		if len(refs) == limit {
			break
		}
	}

	var nextToken string
	if len(refs) == limit {
		nextToken = encodeCursor(last)
	}
	return nextToken, refs, nil
}

// Prune is a no-op for FlatFileStore; space is reclaimed exclusively through
// Evict when the storage limit is reached.
func (s *FlatFileStore) Prune() (int, error) { return 0, nil }

type flatCandidate struct {
	path      string
	expiresAt int64
}

// Evict removes up to n blocks ordered by logical expiry ascending — blocks
// whose PoW-based lifetime ran out longest ago are removed first, preserving
// higher-value (high-PoW) blocks as long as physical space allows.
func (s *FlatFileStore) Evict(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}

	var all []flatCandidate
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if len(d.Name()) != 2*IDSize {
			return nil
		}
		_, _, _, expiresAt, hdrErr := s.readHeader(path)
		if hdrErr != nil {
			return nil
		}
		all = append(all, flatCandidate{path: path, expiresAt: expiresAt})
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("blockstore: flatfile: evict: %w", err)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].expiresAt < all[j].expiresAt
	})

	var evicted int
	for _, c := range all {
		if evicted >= n {
			break
		}
		if err := os.Remove(c.path); err == nil {
			evicted++
		}
	}
	return evicted, nil
}

func (s *FlatFileStore) Close() error { return nil }

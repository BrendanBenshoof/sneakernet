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
//   stamp[4] | work_factor uint32[4] | created_at int64[8] | expires_at int64[8]
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
type FlatFileStore struct {
	root string
}

// OpenFlatFile opens (or creates) a flat-file blockstore rooted at dir.
func OpenFlatFile(dir string) (*FlatFileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("blockstore: flatfile: mkdir: %w", err)
	}
	return &FlatFileStore{root: dir}, nil
}

func (s *FlatFileStore) blockPath(id ID) string {
	h := hex.EncodeToString(id[:])
	return filepath.Join(s.root, h[:2], h[2:4], h)
}

func (s *FlatFileStore) Put(stamp Stamp, payload Payload) (ID, error) {
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
	expiresAt := int64(binary.BigEndian.Uint64(buf[StampSize+12 : StampSize+20]))
	if time.Now().Unix() > expiresAt {
		return Stamp{}, Payload{}, ErrNotFound
	}
	var stamp Stamp
	var payload Payload
	copy(stamp[:], buf[:StampSize])
	copy(payload[:], buf[flatHeaderSize:])
	return stamp, payload, nil
}

func (s *FlatFileStore) Has(id ID) (bool, error) {
	_, _, _, expiresAt, err := s.readHeader(s.blockPath(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return time.Now().Unix() <= expiresAt, nil
}

func (s *FlatFileStore) ListIDs() ([]ID, error) {
	now := time.Now().Unix()
	var ids []ID
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		idBytes, decErr := hex.DecodeString(d.Name())
		if decErr != nil || len(idBytes) != IDSize {
			return nil
		}
		_, _, _, expiresAt, hdrErr := s.readHeader(path)
		if hdrErr != nil || now > expiresAt {
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
	now := time.Now().Unix()
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
		_, wf, createdAt, expiresAt, hdrErr := s.readHeader(path)
		if hdrErr != nil || now > expiresAt || wf < powFloor || createdAt < sinceUnix {
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

func (s *FlatFileStore) Prune() (int, error) {
	now := time.Now().Unix()
	count := 0
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
		if now > expiresAt {
			if removeErr := os.Remove(path); removeErr == nil {
				count++
			}
		}
		return nil
	})
	return count, err
}

func (s *FlatFileStore) Close() error { return nil }

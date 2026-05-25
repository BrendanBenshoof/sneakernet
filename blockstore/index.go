package blockstore

import (
	"bytes"
	"compress/zlib"
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

const (
	indexMagic   = "SNK1"
	indexRecSize = 38 // id[32] + wf[1] + expires_at[4] + flags[1]

	// shardThreshold is the record count above which BuildIndex automatically
	// switches to sharded mode to stay under FAT32's 4 GB file limit.
	shardThreshold = 10_000_000
)

// IndexRecord is one entry in the binary block index.
type IndexRecord struct {
	ID        ID
	WorkFactor uint8
	ExpiresAt  uint32 // unix seconds; uint32 is valid until 2106
}

func (r IndexRecord) isExpired() bool {
	return uint32(time.Now().Unix()) > r.ExpiresAt
}

// BuildIndex scans a FlatFileStore root and writes a compressed binary index.
// It writes a single index.bin for stores under shardThreshold records, and
// 256 sharded index/{xx}.bin files for larger stores.
func BuildIndex(storeRoot string) error {
	records, err := scanRecords(storeRoot)
	if err != nil {
		return fmt.Errorf("blockstore: index: scan: %w", err)
	}
	sort.Slice(records, func(i, j int) bool {
		return bytes.Compare(records[i].ID[:], records[j].ID[:]) < 0
	})
	if len(records) >= shardThreshold {
		return writeShards(storeRoot, records)
	}
	return writeSingleIndex(filepath.Join(storeRoot, "index.bin"), records)
}

// OpenIndex opens a single compressed index file for querying.
// For sharded stores, open each shard with OpenIndex separately.
func OpenIndex(path string) (*Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("blockstore: index: open: %w", err)
	}
	defer f.Close()

	zr, err := zlib.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("blockstore: index: zlib: %w", err)
	}
	defer zr.Close()

	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("blockstore: index: read: %w", err)
	}
	return parseIndex(data)
}

// Index is a decoded, queryable block index loaded from a single shard file.
type Index struct {
	records []IndexRecord
}

// Has returns true if the index contains a non-expired block with the given ID.
func (idx *Index) Has(id ID) bool {
	r, ok := idx.search(id)
	return ok && !r.isExpired()
}

// Records returns all non-expired records in sorted order.
func (idx *Index) Records() []IndexRecord {
	now := uint32(time.Now().Unix())
	out := make([]IndexRecord, 0, len(idx.records))
	for _, r := range idx.records {
		if r.ExpiresAt > now {
			out = append(out, r)
		}
	}
	return out
}

// Len returns the total number of records (including expired) in this index shard.
func (idx *Index) Len() int { return len(idx.records) }

func (idx *Index) search(id ID) (IndexRecord, bool) {
	n := len(idx.records)
	lo, hi := 0, n
	for lo < hi {
		mid := (lo + hi) / 2
		cmp := bytes.Compare(idx.records[mid].ID[:], id[:])
		switch {
		case cmp == 0:
			return idx.records[mid], true
		case cmp < 0:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return IndexRecord{}, false
}

// --- internal helpers ---

func scanRecords(storeRoot string) ([]IndexRecord, error) {
	now := uint32(time.Now().Unix())
	var records []IndexRecord

	err := filepath.WalkDir(storeRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if len(d.Name()) != 2*IDSize {
			return nil // skip non-block files (e.g. index.bin, *.tmp)
		}
		_, wf, _, expiresAt, hdrErr := (&FlatFileStore{root: storeRoot}).readHeader(path)
		if hdrErr != nil {
			return nil
		}
		if now > uint32(expiresAt) {
			return nil
		}

		idBytes, err := hex.DecodeString(d.Name())
		if err != nil || len(idBytes) != IDSize {
			return nil
		}
		var id ID
		copy(id[:], idBytes)
		records = append(records, IndexRecord{
			ID:         id,
			WorkFactor: uint8(wf),
			ExpiresAt:  uint32(expiresAt),
		})
		return nil
	})
	return records, err
}

func writeSingleIndex(path string, records []IndexRecord) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("blockstore: index: create: %w", err)
	}
	if err := encodeIndex(f, records); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ShardName returns the filename (e.g. "ab.bin") for the index shard that
// covers the given block ID. Use with filepath.Join(root, "index", ShardName(id)).
func ShardName(id ID) string { return fmt.Sprintf("%02x.bin", id[0]) }

// BuildShardedIndex always writes 256 shards regardless of record count.
// Use this explicitly when single-file mode is not desired.
func BuildShardedIndex(storeRoot string) error {
	records, err := scanRecords(storeRoot)
	if err != nil {
		return fmt.Errorf("blockstore: index: scan: %w", err)
	}
	sort.Slice(records, func(i, j int) bool {
		return bytes.Compare(records[i].ID[:], records[j].ID[:]) < 0
	})
	return writeShards(storeRoot, records)
}

func writeShards(storeRoot string, records []IndexRecord) error {
	shardDir := filepath.Join(storeRoot, "index")
	if err := os.MkdirAll(shardDir, 0o755); err != nil {
		return fmt.Errorf("blockstore: index: shards mkdir: %w", err)
	}
	// Partition sorted records by first ID byte (already sorted).
	i := 0
	for b := 0; b < 256; b++ {
		j := i
		for j < len(records) && records[j].ID[0] == byte(b) {
			j++
		}
		path := filepath.Join(shardDir, fmt.Sprintf("%02x.bin", b))
		if err := writeSingleIndex(path, records[i:j]); err != nil {
			return err
		}
		i = j
	}
	return nil
}

func encodeIndex(w io.Writer, records []IndexRecord) error {
	zw := zlib.NewWriter(w)

	var hdr [8]byte
	copy(hdr[:4], indexMagic)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(records)))
	if _, err := zw.Write(hdr[:]); err != nil {
		zw.Close()
		return fmt.Errorf("blockstore: index: write header: %w", err)
	}

	var rec [indexRecSize]byte
	for _, r := range records {
		copy(rec[:IDSize], r.ID[:])
		rec[IDSize] = r.WorkFactor
		binary.BigEndian.PutUint32(rec[IDSize+1:IDSize+5], r.ExpiresAt)
		rec[IDSize+5] = 0 // flags reserved
		if _, err := zw.Write(rec[:]); err != nil {
			zw.Close()
			return fmt.Errorf("blockstore: index: write record: %w", err)
		}
	}
	return zw.Close()
}

func parseIndex(data []byte) (*Index, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("blockstore: index: truncated header")
	}
	if string(data[:4]) != indexMagic {
		return nil, fmt.Errorf("blockstore: index: bad magic %q", data[:4])
	}
	count := int(binary.BigEndian.Uint32(data[4:8]))
	data = data[8:]

	if len(data) < count*indexRecSize {
		return nil, fmt.Errorf("blockstore: index: expected %d records, got %d bytes", count, len(data))
	}

	records := make([]IndexRecord, count)
	for i := range records {
		off := i * indexRecSize
		var id ID
		copy(id[:], data[off:off+IDSize])
		records[i] = IndexRecord{
			ID:         id,
			WorkFactor: data[off+IDSize],
			ExpiresAt:  binary.BigEndian.Uint32(data[off+IDSize+1 : off+IDSize+5]),
		}
	}
	return &Index{records: records}, nil
}



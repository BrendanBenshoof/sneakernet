package blockstore

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a SQLite-backed implementation of Store.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) a SQLite blockstore at path.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS blocks (
			id          BLOB    PRIMARY KEY,
			stamp       BLOB    NOT NULL,
			payload     BLOB    NOT NULL,
			work_factor INTEGER NOT NULL,
			created_at  INTEGER NOT NULL,
			expires_at  INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_expires   ON blocks(expires_at);
		CREATE INDEX IF NOT EXISTS idx_traversal ON blocks(work_factor, created_at, id);
	`)
	return err
}

func (s *SQLiteStore) Put(stamp Stamp, payload Payload) (ID, error) {
	id := ComputeID(payload)
	wf := WorkFactor(stamp, payload)
	now := time.Now()
	expiresAt := now.Add(TTLFromWorkFactor(wf))

	_, err := s.db.Exec(
		`INSERT INTO blocks (id, stamp, payload, work_factor, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     stamp       = excluded.stamp,
		     work_factor = excluded.work_factor,
		     created_at  = excluded.created_at,
		     expires_at  = excluded.expires_at
		 WHERE excluded.work_factor > blocks.work_factor`,
		id[:], stamp[:], payload[:], wf, now.Unix(), expiresAt.Unix(),
	)
	if err != nil {
		return ID{}, fmt.Errorf("blockstore: put: %w", err)
	}
	return id, nil
}

func (s *SQLiteStore) Get(id ID) (Stamp, Payload, error) {
	var stampBytes, payloadBytes []byte
	err := s.db.QueryRow(
		`SELECT stamp, payload FROM blocks WHERE id = ? AND expires_at > ?`,
		id[:], time.Now().Unix(),
	).Scan(&stampBytes, &payloadBytes)

	if err == sql.ErrNoRows {
		return Stamp{}, Payload{}, ErrNotFound
	}
	if err != nil {
		return Stamp{}, Payload{}, fmt.Errorf("blockstore: get: %w", err)
	}

	var stamp Stamp
	var payload Payload
	copy(stamp[:], stampBytes)
	copy(payload[:], payloadBytes)
	return stamp, payload, nil
}

func (s *SQLiteStore) Has(id ID) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(1) FROM blocks WHERE id = ? AND expires_at > ?`,
		id[:], time.Now().Unix(),
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("blockstore: has: %w", err)
	}
	return count > 0, nil
}

func (s *SQLiteStore) ListIDs() ([]ID, error) {
	rows, err := s.db.Query(
		`SELECT id FROM blocks WHERE expires_at > ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("blockstore: listids: %w", err)
	}
	defer rows.Close()

	var ids []ID
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, fmt.Errorf("blockstore: listids: %w", err)
		}
		var id ID
		copy(id[:], b)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *SQLiteStore) ListBlocks(pageToken string, limit int, powFloor int, since time.Time) (string, []BlockRef, error) {
	now := time.Now().Unix()
	sinceUnix := since.Unix()

	var (
		rows *sql.Rows
		err  error
	)

	if pageToken == "" {
		rows, err = s.db.Query(
			`SELECT id, work_factor, created_at FROM blocks
			 WHERE expires_at > ? AND work_factor >= ? AND created_at >= ?
			 ORDER BY created_at ASC, id ASC
			 LIMIT ?`,
			now, powFloor, sinceUnix, limit,
		)
	} else {
		cur, curErr := decodeCursor(pageToken)
		if curErr != nil {
			return "", nil, curErr
		}
		rows, err = s.db.Query(
			`SELECT id, work_factor, created_at FROM blocks
			 WHERE expires_at > ? AND work_factor >= ? AND created_at >= ?
			   AND (created_at > ? OR (created_at = ? AND id > ?))
			 ORDER BY created_at ASC, id ASC
			 LIMIT ?`,
			now, powFloor, sinceUnix,
			cur.createdAt, cur.createdAt, cur.id[:],
			limit,
		)
	}
	if err != nil {
		return "", nil, fmt.Errorf("blockstore: listblocks: %w", err)
	}
	defer rows.Close()

	var refs []BlockRef
	var last cursor
	for rows.Next() {
		var idBytes []byte
		var wf int
		var createdAt int64
		if err := rows.Scan(&idBytes, &wf, &createdAt); err != nil {
			return "", nil, fmt.Errorf("blockstore: listblocks: %w", err)
		}
		var ref BlockRef
		copy(ref.ID[:], idBytes)
		ref.WorkFactor = wf
		ref.CreatedAt = createdAt
		refs = append(refs, ref)
		last.createdAt = createdAt
		last.id = ref.ID
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("blockstore: listblocks: %w", err)
	}

	var nextToken string
	if len(refs) == limit {
		nextToken = encodeCursor(last)
	}
	return nextToken, refs, nil
}

func (s *SQLiteStore) Prune() (int, error) {
	result, err := s.db.Exec(
		`DELETE FROM blocks WHERE expires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("blockstore: prune: %w", err)
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

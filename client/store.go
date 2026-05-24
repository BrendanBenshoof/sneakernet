package client

import (
	"bytes"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// Message is a successfully decrypted and (for fragments) fully reassembled message.
type Message struct {
	ID         int64
	BlockID    blockstore.ID // first block seen; for reassembled fragments, the first fragment's block
	SenderPub  [32]byte      // Ed25519 public key; all-zeros = anonymous
	ThreadRefs [8][32]byte   // skip list; ThreadRefs[0] is direct reply target; all-zeros = absent
	SentAt     time.Time     // sender-claimed send time; zero = unknown
	MsgType    uint8
	Content    []byte
	ReceivedAt time.Time
}

// MessageStore persists received messages and the scrape checkpoint.
type MessageStore struct {
	db *sql.DB
}

// OpenMessageStore opens (or creates) a SQLite message store at path.
func OpenMessageStore(path string) (*MessageStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &MessageStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *MessageStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			block_id    BLOB    NOT NULL UNIQUE,
			content     BLOB    NOT NULL,
			received_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS checkpoint (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			since_unix INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO checkpoint (id, since_unix) VALUES (1, 0);
	`)
	if err != nil {
		return err
	}

	// Additive columns — each wrapped in an existence check so migrate() is idempotent.
	addCols := []struct{ name, def string }{
		{"sender_pub", "BLOB DEFAULT NULL"},
		{"thread_refs", "BLOB DEFAULT NULL"},
		{"sent_at", "INTEGER DEFAULT NULL"},
		{"msg_type", "INTEGER NOT NULL DEFAULT 0"},
		{"frag_id", "BLOB DEFAULT NULL"},
	}
	for _, col := range addCols {
		var count int
		row := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = ?`, col.name)
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf("client: migrate check column %q: %w", col.name, err)
		}
		if count == 0 {
			if _, err := s.db.Exec(`ALTER TABLE messages ADD COLUMN ` + col.name + ` ` + col.def); err != nil {
				return fmt.Errorf("client: migrate add column %q: %w", col.name, err)
			}
		}
	}

	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS fragments (
			frag_id     BLOB    NOT NULL,
			frag_index  INTEGER NOT NULL,
			frag_total  INTEGER NOT NULL,
			block_id    BLOB    NOT NULL,
			content     BLOB    NOT NULL,
			sender_pub  BLOB,
			thread_refs BLOB,
			sent_at     INTEGER,
			msg_type    INTEGER NOT NULL DEFAULT 0,
			received_at INTEGER NOT NULL,
			PRIMARY KEY (frag_id, frag_index)
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_frag_assembled
			ON messages(frag_id) WHERE frag_id IS NOT NULL;
	`)
	return err
}

// GetCheckpoint returns the timestamp from which the next scrape should start.
func (s *MessageStore) GetCheckpoint() (time.Time, error) {
	var unix int64
	err := s.db.QueryRow(`SELECT since_unix FROM checkpoint WHERE id = 1`).Scan(&unix)
	if err != nil {
		return time.Time{}, fmt.Errorf("client: get checkpoint: %w", err)
	}
	if unix == 0 {
		return time.Time{}, nil
	}
	return time.Unix(unix, 0), nil
}

// SetCheckpoint records t as the start-of-next-scrape watermark.
func (s *MessageStore) SetCheckpoint(t time.Time) error {
	_, err := s.db.Exec(`UPDATE checkpoint SET since_unix = ? WHERE id = 1`, t.Unix())
	if err != nil {
		return fmt.Errorf("client: set checkpoint: %w", err)
	}
	return nil
}

// SaveMessage persists a decoded single-block message. Returns true if newly inserted.
func (s *MessageStore) SaveMessage(blockID blockstore.ID, mp MessagePayload) (bool, error) {
	result, err := s.db.Exec(
		`INSERT OR IGNORE INTO messages
			(block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
		blockID[:],
		mp.Content,
		time.Now().Unix(),
		zeroToNil(mp.SenderPub[:]),
		encodeThreadRefs(mp.ThreadRefs),
		zeroInt64(mp.Timestamp),
		mp.MsgType,
	)
	if err != nil {
		return false, fmt.Errorf("client: save message: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// SaveFragment stores one fragment. If this completes the set, all fragments are
// assembled into a single message, fragment rows are cleaned up, and (true, nil)
// is returned. Otherwise returns (false, nil).
func (s *MessageStore) SaveFragment(blockID blockstore.ID, mp MessagePayload) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("client: save fragment: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT OR IGNORE INTO fragments
			(frag_id, frag_index, frag_total, block_id, content,
			 sender_pub, thread_refs, sent_at, msg_type, received_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		mp.FragID[:],
		mp.FragIndex,
		mp.FragTotal,
		blockID[:],
		mp.Content,
		zeroToNil(mp.SenderPub[:]),
		encodeThreadRefs(mp.ThreadRefs),
		zeroInt64(mp.Timestamp),
		mp.MsgType,
		time.Now().Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("client: save fragment: insert: %w", err)
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM fragments WHERE frag_id = ?`, mp.FragID[:]).Scan(&count); err != nil {
		return false, fmt.Errorf("client: save fragment: count: %w", err)
	}
	if count < int(mp.FragTotal) {
		return false, tx.Commit()
	}

	// All fragments present — assemble in order.
	rows, err := tx.Query(
		`SELECT frag_index, block_id, content FROM fragments WHERE frag_id = ? ORDER BY frag_index ASC`,
		mp.FragID[:],
	)
	if err != nil {
		return false, fmt.Errorf("client: save fragment: query: %w", err)
	}
	var buf bytes.Buffer
	var firstBlockID blockstore.ID
	for rows.Next() {
		var idx int
		var bidBytes, chunk []byte
		if err := rows.Scan(&idx, &bidBytes, &chunk); err != nil {
			rows.Close()
			return false, fmt.Errorf("client: save fragment: scan: %w", err)
		}
		if idx == 0 {
			copy(firstBlockID[:], bidBytes)
		}
		buf.Write(chunk)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("client: save fragment: rows: %w", err)
	}

	res, err := tx.Exec(
		`INSERT OR IGNORE INTO messages
			(block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type, frag_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		firstBlockID[:],
		buf.Bytes(),
		time.Now().Unix(),
		zeroToNil(mp.SenderPub[:]),
		encodeThreadRefs(mp.ThreadRefs),
		zeroInt64(mp.Timestamp),
		mp.MsgType,
		mp.FragID[:],
	)
	if err != nil {
		return false, fmt.Errorf("client: save fragment: insert message: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM fragments WHERE frag_id = ?`, mp.FragID[:]); err != nil {
		return false, fmt.Errorf("client: save fragment: cleanup: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("client: save fragment: commit: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetMessage looks up a single message by block ID. Returns (Message{}, false, nil) if not found.
func (s *MessageStore) GetMessage(blockID blockstore.ID) (Message, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type
		 FROM messages WHERE block_id = ?`,
		blockID[:],
	)
	m, err := scanMessage(row)
	if err == sql.ErrNoRows {
		return Message{}, false, nil
	}
	if err != nil {
		return Message{}, false, fmt.Errorf("client: get message: %w", err)
	}
	return m, true, nil
}

// ListMessages returns all stored messages ordered by receipt time.
func (s *MessageStore) ListMessages() ([]Message, error) {
	return s.ListMessagesAfter(0)
}

// ListMessagesAfter returns messages with id > afterID, ordered by receipt time.
func (s *MessageStore) ListMessagesAfter(afterID int64) ([]Message, error) {
	rows, err := s.db.Query(
		`SELECT id, block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type
		 FROM messages WHERE id > ? ORDER BY received_at ASC`,
		afterID,
	)
	if err != nil {
		return nil, fmt.Errorf("client: list messages: %w", err)
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("client: list messages: %w", err)
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// Close releases the underlying database connection.
func (s *MessageStore) Close() error {
	return s.db.Close()
}

// --- helpers ---

type scanner interface {
	Scan(dest ...any) error
}

func scanMessage(s scanner) (Message, error) {
	var m Message
	var blockBytes []byte
	var unix int64
	var senderPub []byte
	var threadRefsBlob []byte
	var sentAt sql.NullInt64
	var msgType int

	err := s.Scan(&m.ID, &blockBytes, &m.Content, &unix,
		&senderPub, &threadRefsBlob, &sentAt, &msgType)
	if err != nil {
		return Message{}, err
	}
	copy(m.BlockID[:], blockBytes)
	m.ReceivedAt = time.Unix(unix, 0)
	copy(m.SenderPub[:], senderPub) // safe: copy copies min(dst, src) bytes
	m.ThreadRefs = decodeThreadRefs(threadRefsBlob)
	if sentAt.Valid {
		m.SentAt = time.Unix(sentAt.Int64, 0)
	}
	m.MsgType = uint8(msgType)
	return m, nil
}

// encodeThreadRefs serialises [8][32]byte to a 256-byte blob; nil if all-zeros.
func encodeThreadRefs(refs [8][32]byte) []byte {
	var zero [8][32]byte
	if refs == zero {
		return nil
	}
	var buf [256]byte
	for i, ref := range refs {
		copy(buf[i*32:(i+1)*32], ref[:])
	}
	return buf[:]
}

// decodeThreadRefs deserialises a 256-byte blob to [8][32]byte.
func decodeThreadRefs(b []byte) [8][32]byte {
	var refs [8][32]byte
	if len(b) < 256 {
		return refs
	}
	for i := range refs {
		copy(refs[i][:], b[i*32:(i+1)*32])
	}
	return refs
}

// zeroToNil returns nil when b is all-zeros, otherwise b. Used to store
// absent optional fields as SQL NULL rather than zero blobs.
func zeroToNil(b []byte) []byte {
	for _, v := range b {
		if v != 0 {
			return b
		}
	}
	return nil
}

// zeroInt64 returns nil when v is 0, otherwise v, for nullable integers.
func zeroInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

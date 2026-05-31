package client

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// Message is a successfully decrypted message.
type Message struct {
	ID          int64
	BlockID     blockstore.ID
	SenderPub   [32]byte      // Ed25519 public key; all-zeros = anonymous
	ThreadRefs  [8][32]byte   // skip list; ThreadRefs[0] is direct reply target; all-zeros = absent
	SentAt      time.Time     // sender-claimed send time; zero = unknown
	MsgType     uint8
	Content     []byte
	Channel     string // empty for direct messages; channel name for channel messages
	ReceivedAt  time.Time
	SentTo      []byte // raw X25519 pub of recipient; set for sent messages, nil for received
	DecryptedBy string // local identity name that decrypted (or sent) the message; empty = channel or anonymous
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
	if _, err := s.db.Exec(`
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
	`); err != nil {
		return err
	}

	// Additive columns — each wrapped in an existence check so migrate() is idempotent.
	addCols := []struct{ name, def string }{
		{"sender_pub", "BLOB DEFAULT NULL"},
		{"thread_refs", "BLOB DEFAULT NULL"},
		{"sent_at", "INTEGER DEFAULT NULL"},
		{"msg_type", "INTEGER NOT NULL DEFAULT 0"},
		{"channel", "TEXT NOT NULL DEFAULT ''"},
		{"sent_to", "BLOB DEFAULT NULL"},
		{"decrypted_by", "TEXT NOT NULL DEFAULT ''"},
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

	return nil
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
			(block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type, channel, sent_to, decrypted_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		blockID[:],
		mp.Content,
		time.Now().Unix(),
		zeroToNil(mp.SenderPub[:]),
		encodeThreadRefs(mp.ThreadRefs),
		zeroInt64(mp.Timestamp),
		mp.MsgType,
		mp.Channel,
		zeroToNil(mp.SentTo),
		mp.DecryptedBy,
	)
	if err != nil {
		return false, fmt.Errorf("client: save message: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// GetMessage looks up a single message by block ID. Returns (Message{}, false, nil) if not found.
func (s *MessageStore) GetMessage(blockID blockstore.ID) (Message, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type, channel, sent_to, decrypted_by
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
		`SELECT id, block_id, content, received_at, sender_pub, thread_refs, sent_at, msg_type, channel, sent_to, decrypted_by
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
		&senderPub, &threadRefsBlob, &sentAt, &msgType, &m.Channel,
		&m.SentTo, &m.DecryptedBy)
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

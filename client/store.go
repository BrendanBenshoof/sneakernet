package client

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/brendanbenshoof/sneakernet/blockstore"
)

// Message is a successfully decrypted block payload.
type Message struct {
	ID         int64
	BlockID    blockstore.ID
	Content    []byte
	Channel    string // empty for direct messages; channel name for channel messages
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
	// Add channel column to existing databases; ignore "duplicate column" error.
	s.db.Exec(`ALTER TABLE messages ADD COLUMN channel TEXT NOT NULL DEFAULT ''`)
	return nil
}

// GetCheckpoint returns the timestamp from which the next scrape should start.
// Returns the zero time on first run (scan all blocks).
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

// SaveMessage persists a decoded message. Returns true if the message was newly
// inserted, false if it was already stored. INSERT OR IGNORE makes it idempotent
// so re-scanning a block (e.g. due to checkpoint granularity) never produces duplicates.
// channel is empty for direct messages, or the channel name for channel messages.
func (s *MessageStore) SaveMessage(blockID blockstore.ID, content []byte, channel string) (bool, error) {
	result, err := s.db.Exec(
		`INSERT OR IGNORE INTO messages (block_id, content, channel, received_at) VALUES (?, ?, ?, ?)`,
		blockID[:], content, channel, time.Now().Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("client: save message: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// ListMessages returns all stored messages ordered by receipt time.
func (s *MessageStore) ListMessages() ([]Message, error) {
	return s.ListMessagesAfter(0)
}

// ListMessagesAfter returns messages with id > afterID, ordered by receipt time.
// Pass 0 to retrieve all messages. Suitable for simple poll-based pagination.
func (s *MessageStore) ListMessagesAfter(afterID int64) ([]Message, error) {
	rows, err := s.db.Query(
		`SELECT id, block_id, content, channel, received_at FROM messages WHERE id > ? ORDER BY received_at ASC`,
		afterID,
	)
	if err != nil {
		return nil, fmt.Errorf("client: list messages: %w", err)
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		var blockBytes []byte
		var unix int64
		if err := rows.Scan(&m.ID, &blockBytes, &m.Content, &m.Channel, &unix); err != nil {
			return nil, fmt.Errorf("client: list messages: %w", err)
		}
		copy(m.BlockID[:], blockBytes)
		m.ReceivedAt = time.Unix(unix, 0)
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// Close releases the underlying database connection.
func (s *MessageStore) Close() error {
	return s.db.Close()
}

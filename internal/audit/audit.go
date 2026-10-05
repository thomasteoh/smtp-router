// Package audit records each send in an embedded SQLite database. The log is
// durable across restarts and stores only metadata — never message content.
package audit

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO)
)

// Status values recorded per send.
const (
	StatusDelivered   = "delivered"
	StatusRateLimited = "rate_limited"
	StatusError       = "error"
	StatusDenied      = "denied"
)

// Store is a durable audit log backed by SQLite.
type Store struct {
	db *sql.DB
}

// Open opens (and creates if needed) the SQLite audit database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	// SQLite concurrency: serialize writes with a busy timeout.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL,
		client TEXT NOT NULL,
		from_addr TEXT NOT NULL,
		provider TEXT NOT NULL,
		status TEXT NOT NULL,
		error TEXT NOT NULL DEFAULT '',
		request_id TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		return nil, fmt.Errorf("create audit table: %w", err)
	}
	return &Store{db: db}, nil
}

// Record writes one audit row. It never logs message content.
func (s *Store) Record(client, from, provider, status, errMsg, requestID string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO audit (ts, client, from_addr, provider, status, error, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ts, client, from, provider, status, errMsg, requestID)
	if err != nil {
		return fmt.Errorf("record audit: %w", err)
	}
	return nil
}

// Row is one audit entry.
type Row struct {
	ID        int64
	TS        string
	Client    string
	From      string
	Provider  string
	Status    string
	Error     string
	RequestID string
}

// List returns the most recent audit rows, newest first, limited to n
// (0 = all).
func (s *Store) List(n int) ([]Row, error) {
	q := "SELECT id, ts, client, from_addr, provider, status, error, request_id FROM audit ORDER BY id DESC"
	if n > 0 {
		// #nosec G202 -- n is an int formatted with %d (no string interpolation),
		// so no SQL injection is possible.
		q += fmt.Sprintf(" LIMIT %d", n)
	}
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.ID, &r.TS, &r.Client, &r.From, &r.Provider, &r.Status, &r.Error, &r.RequestID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Count returns the number of rows in a given status (empty = all).
func (s *Store) Count(status string) (int, error) {
	q := "SELECT COUNT(*) FROM audit"
	if status != "" {
		q += " WHERE status = ?"
	}
	var n int
	var err error
	if status != "" {
		err = s.db.QueryRow(q, status).Scan(&n)
	} else {
		err = s.db.QueryRow(q).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("count audit: %w", err)
	}
	return n, nil
}

// Prune removes rows older than the given cutoff (0 disables). Returns rows
// removed.
func (s *Store) Prune(cutoff time.Time) (int, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	res, err := s.db.Exec("DELETE FROM audit WHERE ts < ?", cutoff.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("prune audit: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Package queue provides a durable send queue with a worker pool. Sends are
// enqueued as jobs in SQLite, then drained by a pool of workers that apply
// per-account rate limits and deliver through providers. The queue enables
// asynchronous sends, deferred (scheduled) sends, prioritisation, retry with
// backoff, and pacing sends to respect provider quotas instead of rejecting
// them outright.
package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO)
)

// Job status values.
const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusDelivered = "delivered"
	StatusDead     = "dead"
)

// Attachment mirrors the provider attachment shape for persistence.
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	ContentB64  string `json:"content_b64"`
}

// Job is one queued send. To and Attachments are stored as JSON in SQLite.
type Job struct {
	ID          int64
	RequestID   string
	Client      string
	From        string
	To          []string
	Subject     string
	Body        string
	HTML        string
	Attachments []Attachment
	Provider    string // optional override; empty = account default
	Priority    int    // higher = more urgent (drained first)
	SendAt      time.Time
	Attempts    int
	Status      string
	Error       string
	CreatedAt   time.Time
	NextAttempt time.Time
}

// RateLimitedError signals that a send was refused by a rate limiter at
// delivery time. The pool re-queues the job without counting it as a failed
// attempt, waiting for the quota window to free.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s", e.RetryAfter)
}

// IsRateLimited reports whether err is (or wraps) a RateLimitedError.
func IsRateLimited(err error) bool {
	var rl *RateLimitedError
	return errors.As(err, &rl)
}

// Stats are aggregate queue counters.
type Stats struct {
	Queued   int
	Running  int
	Delivered int64
	Dead     int64
	Retries  int64
	Workers  int
	MaxSize  int
	MaxRetries int
}

// Store is a durable job queue backed by SQLite.
type Store struct {
	db *sql.DB
}

// Open opens (and creates if needed) the queue database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open queue db: %w", err)
	}
	// Serialize writes; SQLite is single-writer.
	db.SetMaxOpenConns(1)
	schema := `
CREATE TABLE IF NOT EXISTS jobs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	request_id TEXT NOT NULL DEFAULT '',
	client TEXT NOT NULL,
	from_addr TEXT NOT NULL,
	to_addr TEXT NOT NULL DEFAULT '[]',
	subject TEXT NOT NULL DEFAULT '',
	body TEXT NOT NULL DEFAULT '',
	html TEXT NOT NULL DEFAULT '',
	attachments TEXT NOT NULL DEFAULT '[]',
	provider TEXT NOT NULL DEFAULT '',
	priority INTEGER NOT NULL DEFAULT 0,
	send_at TEXT NOT NULL DEFAULT '',
	attempts INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'queued',
	error TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	next_attempt TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_ready ON jobs(status, send_at, next_attempt);
CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(status, priority DESC, id);
`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create queue schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Enqueue inserts a job and returns its ID. The job's CreatedAt, Status and
// NextAttempt are set here; ID is populated on return.
func (s *Store) Enqueue(j Job) (int64, error) {
	now := time.Now().UTC()
	if j.Status == "" {
		j.Status = StatusQueued
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	if j.SendAt.IsZero() && j.NextAttempt.IsZero() {
		j.NextAttempt = now
	}
	to, _ := json.Marshal(j.To)
	atts, _ := json.Marshal(j.Attachments)
	res, err := s.db.Exec(`INSERT INTO jobs
		(request_id, client, from_addr, to_addr, subject, body, html, attachments,
		 provider, priority, send_at, attempts, status, error, created_at, next_attempt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.RequestID, j.Client, j.From, string(to), j.Subject, j.Body, j.HTML, string(atts),
		j.Provider, j.Priority, rfc3339OrEmpty(j.SendAt), j.Attempts, j.Status, j.Error,
		j.CreatedAt.UTC().Format(time.RFC3339), rfc3339OrEmpty(j.NextAttempt))
	if err != nil {
		return 0, fmt.Errorf("enqueue job: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// Claim selects up to limit ready jobs and marks them running in a single
// transaction. Ready means status=queued and (no send_at or send_at<=now) and
// (no next_attempt or next_attempt<=now). Jobs are ordered by priority then ID
// (FIFO within priority).
func (s *Store) Claim(limit int, now time.Time) ([]Job, error) {
	nowStr := now.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("claim begin: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, request_id, client, from_addr, to_addr, subject, body,
		html, attachments, provider, priority, send_at, attempts, status, error,
		created_at, next_attempt
		FROM jobs
		WHERE status = 'queued'
		  AND (send_at = '' OR send_at <= ?)
		  AND (next_attempt = '' OR next_attempt <= ?)
		ORDER BY priority DESC, id ASC
		LIMIT ?`, nowStr, nowStr, limit)
	if err != nil {
		return nil, fmt.Errorf("claim select: %w", err)
	}
	jobs, err := scanJobs(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if _, err := tx.Exec(`UPDATE jobs SET status = 'running', next_attempt = '' WHERE id = ? AND status = 'queued'`, j.ID); err != nil {
			return nil, fmt.Errorf("claim mark: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("claim commit: %w", err)
	}
	// Reflect the running status on the returned jobs.
	for i := range jobs {
		jobs[i].Status = StatusRunning
	}
	return jobs, nil
}

// Finish marks a job terminal (delivered or dead) without incrementing
// attempts.
func (s *Store) Finish(id int64, status, errMsg string) error {
	_, err := s.db.Exec(`UPDATE jobs SET status = ?, error = ? WHERE id = ? AND status = 'running'`, status, errMsg, id)
	if err != nil {
		return fmt.Errorf("finish job: %w", err)
	}
	return nil
}

// Requeue puts a running job back to queued after a failure, incrementing its
// attempt count and scheduling the next attempt.
func (s *Store) Requeue(id int64, next time.Time, errMsg string) error {
	_, err := s.db.Exec(`UPDATE jobs SET status = 'queued', attempts = attempts + 1,
		next_attempt = ?, error = ? WHERE id = ? AND status = 'running'`,
		rfc3339OrEmpty(next), errMsg, id)
	if err != nil {
		return fmt.Errorf("requeue job: %w", err)
	}
	return nil
}

// RequeueRateLimited re-queues a running job after a rate-limit refusal
// WITHOUT counting it as a failed attempt, so a job waits for the quota
// window to free rather than dying.
func (s *Store) RequeueRateLimited(id int64, next time.Time) error {
	_, err := s.db.Exec(`UPDATE jobs SET status = 'queued', next_attempt = ?,
		error = 'rate limited' WHERE id = ? AND status = 'running'`,
		rfc3339OrEmpty(next), id)
	if err != nil {
		return fmt.Errorf("requeue rate limited: %w", err)
	}
	return nil
}

// Recover reclaims jobs left in 'running' (e.g. after a crash/restart) back
// to 'queued' with a small delay, so they are not lost. Returns the number
// reclaimed. Exactly-once delivery is impossible without provider
// idempotency; the delay reduces the risk of double-sending a job that was in
// flight when the process died.
func (s *Store) Recover(delay time.Duration) (int, error) {
	next := time.Now().UTC().Add(delay).Format(time.RFC3339)
	res, err := s.db.Exec(`UPDATE jobs SET status = 'queued', next_attempt = ?
		WHERE status = 'running'`, next)
	if err != nil {
		return 0, fmt.Errorf("recover jobs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Count returns the number of jobs in a status (empty = all non-dead? no:
// empty = all rows).
func (s *Store) Count(status string) (int, error) {
	var n int
	if status == "" {
		err := s.db.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n)
		return n, err
	}
	err := s.db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE status = ?`, status).Scan(&n)
	return n, err
}

// List returns up to limit jobs, newest first, optionally filtered by status.
func (s *Store) List(limit int, status string) ([]Job, error) {
	q := `SELECT id, request_id, client, from_addr, to_addr, subject, body, html,
		attachments, provider, priority, send_at, attempts, status, error,
		created_at, next_attempt FROM jobs`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()
	return scanJobs(rows)
}

// Cancel marks a queued job dead (cancelled). Running jobs cannot be cancelled
// (they are in flight); returns false in that case.
func (s *Store) Cancel(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE jobs SET status = 'dead', error = 'cancelled'
		WHERE id = ? AND status = 'queued'`, id)
	if err != nil {
		return false, fmt.Errorf("cancel job: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// scanJobs reads rows into Jobs.
func scanJobs(rows *sql.Rows) ([]Job, error) {
	var out []Job
	for rows.Next() {
		var j Job
		var to, atts string
		var sendAt, createdAt, nextAt string
		if err := rows.Scan(&j.ID, &j.RequestID, &j.Client, &j.From, &to, &j.Subject,
			&j.Body, &j.HTML, &atts, &j.Provider, &j.Priority, &sendAt, &j.Attempts,
			&j.Status, &j.Error, &createdAt, &nextAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(to), &j.To)
		_ = json.Unmarshal([]byte(atts), &j.Attachments)
		j.SendAt = parseRFC3339(sendAt)
		j.CreatedAt = parseRFC3339(createdAt)
		j.NextAttempt = parseRFC3339(nextAt)
		out = append(out, j)
	}
	return out, rows.Err()
}

// rfc3339OrEmpty formats a time as RFC3339, or empty for zero time.
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// Pool drains the store with a fixed number of workers. The deliver function
// is injected so the pool stays decoupled from providers/audit/webhooks.
type Pool struct {
	store        *Store
	cfg          Config
	deliver      func(context.Context, Job) (string, error)
	workers      int
	batch        int
	maxRetries   int
	retryBase    time.Duration
	recoverDelay time.Duration

	delivered atomic.Int64
	dead      atomic.Int64
	retries   atomic.Int64
}

// Config are pool tuning knobs (mirrors config.Queue).
type Config struct {
	Workers    int
	Batch      int
	MaxSize    int
	MaxRetries int
	RetryBase  time.Duration
}

// Defaults fills zero values with sensible defaults.
func (c *Config) defaults() {
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.Batch <= 0 {
		c.Batch = 8
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
	if c.RetryBase <= 0 {
		c.RetryBase = 30 * time.Second
	}
}

// NewPool builds a Pool. deliver must return the provider name on success.
func NewPool(store *Store, cfg Config, deliver func(context.Context, Job) (string, error)) *Pool {
	cfg.defaults()
	return &Pool{
		store:        store,
		cfg:          cfg,
		deliver:      deliver,
		workers:      cfg.Workers,
		batch:        cfg.Batch,
		maxRetries:   cfg.MaxRetries,
		retryBase:    cfg.RetryBase,
		recoverDelay: 5 * time.Second,
	}
}

// Recover reclaims running jobs from a previous run.
func (p *Pool) Recover() (int, error) {
	return p.store.Recover(p.recoverDelay)
}

// Run starts the worker loop and blocks until ctx is done. Each worker claims
// a batch, delivers sequentially, and marks results. An empty batch is slept
// briefly to avoid busy-looping.
func (p *Pool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				jobs, err := p.store.Claim(p.batch, time.Now().UTC())
				if err != nil {
					// transient DB error: back off and retry.
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
					continue
				}
				if len(jobs) == 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
					continue
				}
				for _, j := range jobs {
					select {
					case <-ctx.Done():
						// Shutdown mid-batch: leave unprocessed jobs queued.
						// The Recover on next start reclaims running ones.
						return
					default:
					}
					p.deliverOne(ctx, j)
				}
			}
		}()
	}
	wg.Wait()
}

// deliverOne delivers a single claimed job and records the outcome.
func (p *Pool) deliverOne(ctx context.Context, j Job) {
	_, err := p.deliver(ctx, j)
	if err == nil {
		_ = p.store.Finish(j.ID, StatusDelivered, "")
		p.delivered.Add(1)
		return
	}
	// Rate limited: re-queue without counting the attempt; wait for quota.
	if IsRateLimited(err) {
		delay := time.Hour
		if rl := new(RateLimitedError); errors.As(err, &rl) && rl.RetryAfter > 0 {
			delay = rl.RetryAfter
		}
		_ = p.store.RequeueRateLimited(j.ID, time.Now().UTC().Add(delay))
		return
	}
	// Real failure: retry with backoff, or mark dead when exhausted.
	if j.Attempts+1 >= p.maxRetries {
		_ = p.store.Finish(j.ID, StatusDead, err.Error())
		p.dead.Add(1)
		return
	}
	backoff := p.retryBase * time.Duration(1<<uint(j.Attempts)) // 1,2,4,...
	if backoff > 10*time.Minute {
		backoff = 10 * time.Minute
	}
	_ = p.store.Requeue(j.ID, time.Now().UTC().Add(backoff), err.Error())
	p.retries.Add(1)
}

// Stats returns aggregate counters and store depth.
func (p *Pool) Stats() (Stats, error) {
	var st Stats
	queued, err := p.store.Count(StatusQueued)
	if err != nil {
		return st, err
	}
	running, err := p.store.Count(StatusRunning)
	if err != nil {
		return st, err
	}
	st.Queued = queued
	st.Running = running
	st.Delivered = p.delivered.Load()
	st.Dead = p.dead.Load()
	st.Retries = p.retries.Load()
	st.Workers = p.workers
	st.MaxSize = p.cfg.MaxSize
	st.MaxRetries = p.maxRetries
	return st, nil
}

// List returns recent jobs, optionally filtered by status.
func (p *Pool) List(limit int, status string) ([]Job, error) {
	return p.store.List(limit, status)
}

// Enqueue submits a job to the store and returns its id. It enforces the
// pool's MaxSize (0 = unlimited): once queued+running jobs reach the cap,
// further jobs are rejected with a clear error so the backlog can't grow
// unbounded.
func (p *Pool) Enqueue(j Job) (int64, error) {
	if p.cfg.MaxSize > 0 {
		depth, err := p.Depth()
		if err != nil {
			return 0, fmt.Errorf("queue depth: %w", err)
		}
		if depth >= p.cfg.MaxSize {
			return 0, fmt.Errorf("queue full (max_size %d, depth %d)", p.cfg.MaxSize, depth)
		}
	}
	return p.store.Enqueue(j)
}

// Cancel cancels a queued job by id; returns false if it is not cancellable.
func (p *Pool) Cancel(id int64) (bool, error) {
	return p.store.Cancel(id)
}

// Depth returns the number of queued+running jobs (backlog).
func (p *Pool) Depth() (int, error) {
	q, err := p.store.Count(StatusQueued)
	if err != nil {
		return 0, err
	}
	r, err := p.store.Count(StatusRunning)
	if err != nil {
		return 0, err
	}
	return q + r, nil
}

// String keeps the package self-describing.
func (j Job) String() string {
	return strings.TrimSpace(j.From + " -> " + strings.Join(j.To, ","))
}

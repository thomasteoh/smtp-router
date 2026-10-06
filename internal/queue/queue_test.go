package queue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mkStore opens an in-memory queue store.
func mkStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func TestEnqueueClaimDeliver(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	id, err := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, Subject: "s"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	jobs, err := s.Claim(10, time.Now().UTC())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != id {
		t.Fatalf("claimed %d, want 1 with id %d", len(jobs), id)
	}
	if jobs[0].Status != StatusRunning {
		t.Fatalf("status = %s, want running", jobs[0].Status)
	}
	if err := s.Finish(id, StatusDelivered, ""); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if n, _ := s.Count(StatusDelivered); n != 1 {
		t.Fatalf("delivered count = %d, want 1", n)
	}
}

func TestPriorityOrdering(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	// Enqueue low first, then high — high must be claimed first.
	if _, err := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, Priority: 1}); err != nil {
		t.Fatalf("enqueue low: %v", err)
	}
	highID, err := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, Priority: 10})
	if err != nil {
		t.Fatalf("enqueue high: %v", err)
	}
	jobs, err := s.Claim(10, time.Now().UTC())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 2 || jobs[0].ID != highID {
		t.Fatalf("priority not honored: first = %d, want %d", jobs[0].ID, highID)
	}
}

func TestFIFOWithinPriority(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	first, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, Priority: 5})
	second, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, Priority: 5})
	jobs, _ := s.Claim(10, time.Now().UTC())
	if jobs[0].ID != first || jobs[1].ID != second {
		t.Fatalf("FIFO broken: got %d,%d want %d,%d", jobs[0].ID, jobs[1].ID, first, second)
	}
}

func TestScheduledNotReady(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	future := time.Now().UTC().Add(time.Hour)
	if _, err := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}, SendAt: future}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Not ready now.
	jobs, _ := s.Claim(10, time.Now().UTC())
	if len(jobs) != 0 {
		t.Fatalf("claimed %d scheduled job too early", len(jobs))
	}
	// Ready after the scheduled time.
	jobs, _ = s.Claim(10, future.Add(time.Second))
	if len(jobs) != 1 {
		t.Fatalf("scheduled job not picked up at due time")
	}
}

func TestRequeueAndDead(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	jobs, _ := s.Claim(10, time.Now().UTC())
	// Requeue after a failure: attempt increments, next_attempt set.
	if err := s.Requeue(id, time.Now().UTC().Add(time.Minute), "boom"); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if n, _ := s.Count(StatusQueued); n != 1 {
		t.Fatalf("queued = %d, want 1", n)
	}
	// Not ready until the next_attempt.
	jobs, _ = s.Claim(10, time.Now().UTC())
	if len(jobs) != 0 {
		t.Fatalf("claimed too early after requeue")
	}
	jobs, _ = s.Claim(10, time.Now().UTC().Add(2*time.Minute))
	if len(jobs) != 1 || jobs[0].Attempts != 1 {
		t.Fatalf("attempt = %d, want 1", jobs[0].Attempts)
	}
	// Finish as dead.
	if err := s.Finish(jobs[0].ID, StatusDead, "exhausted"); err != nil {
		t.Fatalf("finish dead: %v", err)
	}
	if n, _ := s.Count(StatusDead); n != 1 {
		t.Fatalf("dead = %d, want 1", n)
	}
}

func TestRateLimitedRequeueDoesNotCountAttempt(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	jobs, _ := s.Claim(10, time.Now().UTC())
	if err := s.RequeueRateLimited(id, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("requeue rate limited: %v", err)
	}
	// Attempts must NOT increment.
	jobs, _ = s.Claim(10, time.Now().UTC().Add(2*time.Hour))
	if jobs[0].Attempts != 0 {
		t.Fatalf("rate-limited requeue counted an attempt: %d", jobs[0].Attempts)
	}
}

func TestRecoverStaleRunning(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	// Claim leaves it running; simulate a crash.
	jobs, _ := s.Claim(10, time.Now().UTC())
	if jobs[0].Status != StatusRunning {
		t.Fatalf("not running")
	}
	n, err := s.Recover(time.Second)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered %d, want 1", n)
	}
	// Not ready until the recovery delay passes.
	jobs, _ = s.Claim(10, time.Now().UTC())
	if len(jobs) != 0 {
		t.Fatalf("claimed too early after recover")
	}
	jobs, _ = s.Claim(10, time.Now().UTC().Add(2*time.Second))
	if len(jobs) != 1 {
		t.Fatalf("recovered job not re-claimed")
	}
}

func TestCancel(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	ok, err := s.Cancel(id)
	if err != nil || !ok {
		t.Fatalf("cancel: ok=%v err=%v", ok, err)
	}
	if n, _ := s.Count(StatusDead); n != 1 {
		t.Fatalf("dead = %d, want 1", n)
	}
	// A running job cannot be cancelled.
	id2, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	jobs, _ := s.Claim(10, time.Now().UTC())
	if len(jobs) != 1 || jobs[0].ID != id2 {
		t.Fatalf("claim: got %d jobs, want 1 with id %d", len(jobs), id2)
	}
	ok, _ = s.Cancel(jobs[0].ID)
	if ok {
		t.Fatalf("cancelled a running job")
	}
}

func TestPoolDeliverAndRetry(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	attempts := 0
	var mu sync.Mutex
	deliver := func(ctx context.Context, j Job) (string, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		// Fail twice, succeed on third.
		if attempts < 3 {
			return "", errors.New("transient")
		}
		return "smtp", nil
	}
	p := NewPool(s, Config{Workers: 1, MaxRetries: 3, RetryBase: time.Millisecond}, deliver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	go p.Run(ctx)
	// Wait for the job to be delivered.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := s.Count(StatusDelivered); n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n, _ := s.Count(StatusDelivered); n != 1 {
		t.Fatalf("delivered = %d, want 1", n)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestPoolRateLimitedRequeue(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	deliver := func(ctx context.Context, j Job) (string, error) {
		return "", &RateLimitedError{RetryAfter: time.Minute}
	}
	p := NewPool(s, Config{Workers: 1, MaxRetries: 3}, deliver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	go p.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	// Must be queued again (not dead, not delivered), attempts not counted.
	if n, _ := s.Count(StatusQueued); n != 1 {
		t.Fatalf("queued = %d, want 1", n)
	}
	if n, _ := s.Count(StatusDead); n != 0 {
		t.Fatalf("dead = %d, want 0", n)
	}
}

func TestPoolDeadOnExhaustion(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	deliver := func(ctx context.Context, j Job) (string, error) {
		return "", errors.New("always fails")
	}
	p := NewPool(s, Config{Workers: 1, MaxRetries: 2, RetryBase: time.Millisecond}, deliver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	go p.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := s.Count(StatusDead); n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n, _ := s.Count(StatusDead); n != 1 {
		t.Fatalf("dead = %d, want 1", n)
	}
}

func TestPoolRecoverOnStart(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	deliver := func(ctx context.Context, j Job) (string, error) {
		return "smtp", nil
	}
	p := NewPool(s, Config{Workers: 1}, deliver)
	// Simulate a previous run's running job.
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	jobs, _ := s.Claim(10, time.Now().UTC())
	_ = jobs
	// Recover before running.
	n, err := p.Recover()
	if err != nil || n != 1 {
		t.Fatalf("recover: n=%d err=%v", n, err)
	}
}

func TestIsRateLimited(t *testing.T) {
	if !IsRateLimited(&RateLimitedError{}) {
		t.Fatalf("should detect rate limited")
	}
	if IsRateLimited(errors.New("other")) {
		t.Fatalf("false positive")
	}
}

// TestPoolStats ensures Stats aggregates correctly.
func TestPoolStats(t *testing.T) {
	s := mkStore(t)
	defer s.Close()
	p := NewPool(s, Config{Workers: 2, MaxRetries: 4, Batch: 5}, func(ctx context.Context, j Job) (string, error) { return "smtp", nil })
	id, _ := s.Enqueue(Job{Client: "c", From: "a@h.com", To: []string{"b@h.com"}})
	_ = id
	st, err := p.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Queued != 1 || st.Workers != 2 || st.MaxRetries != 4 {
		t.Fatalf("stats = %+v", st)
	}
}

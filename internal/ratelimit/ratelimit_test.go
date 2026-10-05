package ratelimit

import (
	"testing"
	"time"
)

func TestAllowDayLimit(t *testing.T) {
	l := New()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	l.SetNow(func() time.Time { return now })

	// Allow up to 3/day.
	for i := 0; i < 3; i++ {
		if !l.Allow("a@harmonicr.com", 3, 100) {
			t.Fatalf("allow %d: expected true", i)
		}
	}
	if l.Allow("a@harmonicr.com", 3, 100) {
		t.Fatal("expected false after day limit")
	}
}

func TestMonthWindowResets(t *testing.T) {
	l := New()
	// Day limit generous, month limit 2.
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	l.SetNow(func() time.Time { return now })

	if !l.Allow("b@harmonicr.com", 1000, 2) {
		t.Fatal("first allow should pass")
	}
	if !l.Allow("b@harmonicr.com", 1000, 2) {
		t.Fatal("second allow should pass")
	}
	if l.Allow("b@harmonicr.com", 1000, 2) {
		t.Fatal("third should be blocked by month limit")
	}

	// Next month resets the month counter.
	now2 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	l.SetNow(func() time.Time { return now2 })
	if !l.Allow("b@harmonicr.com", 1000, 2) {
		t.Fatal("new month should reset month counter")
	}
}

func TestDayResetsMidnight(t *testing.T) {
	l := New()
	now := time.Date(2026, 10, 5, 23, 0, 0, 0, time.UTC)
	l.SetNow(func() time.Time { return now })

	if !l.Allow("c@harmonicr.com", 1, 1000) {
		t.Fatal("allow 1")
	}
	if l.Allow("c@harmonicr.com", 1, 1000) {
		t.Fatal("should block at day limit")
	}

	// Next day resets.
	now2 := time.Date(2026, 10, 6, 0, 0, 1, 0, time.UTC)
	l.SetNow(func() time.Time { return now2 })
	if !l.Allow("c@harmonicr.com", 1, 1000) {
		t.Fatal("new day should reset day counter")
	}
}

func TestUsage(t *testing.T) {
	l := New()
	l.Allow("d@harmonicr.com", 100, 100)
	d, m := l.Usage("d@harmonicr.com")
	if d != 1 || m != 1 {
		t.Fatalf("usage = day %d month %d, want 1 1", d, m)
	}
}

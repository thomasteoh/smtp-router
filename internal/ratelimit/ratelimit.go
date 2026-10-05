// Package ratelimit enforces per-account send quotas. Each account has two
// independent counters: a day counter (resets at midnight UTC) and a month
// counter (resets at the start of the month, UTC). This accommodates provider
// restrictions that differ between daily and monthly caps.
package ratelimit

import (
	"sync"
	"time"
)

// Window identifies a rate-limit window.
type Window string

const (
	WindowDay   Window = "day"
	WindowMonth Window = "month"
)

// Limiter tracks per-account usage in the two windows.
type Limiter struct {
	mu sync.Mutex
	// accounts maps account -> {window -> {periodKey, count}}
	accounts map[string]*accountState
	// now is injectable for tests.
	now func() time.Time
}

type accountState struct {
	day   periodCount
	month periodCount
}

type periodCount struct {
	period string // e.g. "2026-10-05" or "2026-10"
	count  int
}

// New builds a Limiter. The zero value is not usable — always call New.
func New() *Limiter {
	return &Limiter{
		accounts: make(map[string]*accountState),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// SetNow overrides the clock (for tests).
func (l *Limiter) SetNow(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = f
}

// Allow checks whether account may send, given the limits. If it may, it
// increments the counters and returns true. If not, it returns false and the
// counters are not incremented.
func (l *Limiter) Allow(account string, dayLimit, monthLimit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now().UTC()
	dKey := now.Format("2006-01-02")
	mKey := now.Format("2006-01")

	st := l.accounts[account]
	if st == nil {
		st = &accountState{}
		l.accounts[account] = st
	}

	if st.day.period != dKey {
		st.day = periodCount{period: dKey}
	}
	if st.month.period != mKey {
		st.month = periodCount{period: mKey}
	}

	if dayLimit > 0 && st.day.count >= dayLimit {
		return false
	}
	if monthLimit > 0 && st.month.count >= monthLimit {
		return false
	}

	st.day.count++
	st.month.count++
	return true
}

// Usage returns the current counts for an account in each window.
func (l *Limiter) Usage(account string) (day, month int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.accounts[account]
	if st == nil {
		return 0, 0
	}
	return st.day.count, st.month.count
}

// Reset clears all state (for tests or a manual reset).
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accounts = make(map[string]*accountState)
}

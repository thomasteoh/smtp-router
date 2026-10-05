// Package rules implements sender allow/deny rules. The router evaluates
// these per send: a `from` address must be allowlisted (or match a domain
// pattern) and must not be denylisted.
package rules

import (
	"fmt"
	"strings"
)

// Rules holds the allowlist and denylist for senders.
type Rules struct {
	Allow []string
	Deny  []string
}

// New builds Rules from allow/deny slices.
func New(allow, deny []string) *Rules {
	return &Rules{Allow: allow, Deny: deny}
}

// Check evaluates a from address. It returns a non-nil error with a reason
// when the sender is denied or not allowed.
func (r *Rules) Check(from string) error {
	if r == nil {
		return nil
	}
	f := strings.ToLower(strings.TrimSpace(from))
	for _, d := range r.Deny {
		if match(f, d) {
			return fmt.Errorf("sender %q is denied", from)
		}
	}
	if len(r.Allow) == 0 {
		return nil
	}
	for _, a := range r.Allow {
		if match(f, a) {
			return nil
		}
	}
	return fmt.Errorf("sender %q is not allowed", from)
}

// match reports whether addr matches rule. A rule may be an exact address or
// a domain pattern (e.g. "*@harmonicr.com").
func match(addr, rule string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule == "" {
		return false
	}
	if !strings.Contains(rule, "@") {
		// bare domain: match any address at that domain
		return strings.HasSuffix(addr, "@"+rule)
	}
	if strings.HasPrefix(rule, "*@") {
		return strings.HasSuffix(addr, "@"+rule[2:])
	}
	return addr == rule
}

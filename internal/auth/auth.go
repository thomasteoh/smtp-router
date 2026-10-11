// Package auth validates per-client API keys. Keys are generated (crypto
// random) and stored hashed, so a DB leak does not expose usable keys. Each
// client is an individual key with its own identity, and every send is
// attributed to the client that presented the key.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// Key is a per-client API key.
type Key struct {
	Client string
	Secret string // hashed form
}

// Auth holds the set of valid client keys.
type Auth struct {
	mu      sync.RWMutex
	byHash  map[string]string // hash(secret) -> client name
}

// New builds an empty Auth.
func New() *Auth {
	return &Auth{byHash: make(map[string]string)}
}

// Generate produces a new client key (raw form) and stores its hash. The raw
// form is returned exactly once — the caller is responsible for giving it to
// the client; it is never stored.
func (a *Auth) Generate(client string) (string, error) {
	if client == "" {
		return "", fmt.Errorf("empty client name")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byHash[hash(secret)] = client
	return secret, nil
}

// Add registers an existing key hash for a client (used when loading config).
func (a *Auth) Add(client, secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byHash[hash(secret)] = client
}

// Validate checks a presented key and returns the client name, or an empty
// string when the key is unknown.
func (a *Auth) Validate(key string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	client, ok := a.byHash[hash(key)]
	if !ok {
		return ""
	}
	return client
}

// Clients returns all registered client names.
func (a *Auth) Clients() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.byHash))
	seen := map[string]bool{}
	for _, c := range a.byHash {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// ValidateUserPass checks an SMTP AUTH user/pass pair against the client
// store. username must be an exact client name, password the client's raw
// API key. Returns the client name on success, "" on failure.
func (a *Auth) ValidateUserPass(user, pass string) string {
	if user == "" || pass == "" {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	// byHash maps hash(secret) -> client name. Compute the password hash once
	// and confirm it belongs to the named client (O(1)).
	c, ok := a.byHash[hash(pass)]
	if !ok || c != user {
		return ""
	}
	return c
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// HashHex returns the hex SHA-256 of a raw key, for storage in config.
func HashHex(raw string) string {
	return hash(raw)
}

// Redact returns a display-safe form of a key (first 8 chars + …), for logs.
func Redact(key string) string {
	if len(key) <= 8 {
		return "[redacted]"
	}
	return strings.TrimSpace(key[:4]) + "…"
}

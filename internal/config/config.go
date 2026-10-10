// Package config loads the smtp-router configuration from an environment
// file or YAML. It defines the providers, accounts, rate limits, rules,
// clients (API keys), webhooks, and OIDC settings the router operates with.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Provider is an upstream delivery provider: either SMTP (host/port/auth,
// tls/starttls) or an HTTP API (url/token/method).
type Provider struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "smtp" or "api"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Auth     string `json:"auth"` // SMTP username:password or API token
	URL      string `json:"url"`
	Token    string `json:"token"`
	Method   string `json:"method"`
	TLS      bool   `json:"tls"`      // implicit TLS (SMTPS, port 465)
	StartTLS bool   `json:"starttls"` // upgrade to TLS after EHLO (port 587)
}

// Rate is a per-account quota. Day and Month are independent counters so a
// provider's different restrictions can be accommodated.
type Rate struct {
	Day   int `json:"day"`
	Month int `json:"month"`
}

// AllocEntry is one weighted provider in an account's allocation list.
type AllocEntry struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"` // relative weight (0 = treated as 1)
}

// Account is a sending account (a `from` address) plus its provider routing
// and per-account rate limits. Either Provider (single) or Allocation
// (weighted list) is used for delivery.
type Account struct {
	From       string       `json:"from"`
	Provider   string       `json:"provider"`
	Allocation []AllocEntry `json:"allocation,omitempty"` // weighted providers
	Rate       Rate         `json:"rate"`
}

// Webhook is an outgoing notification endpoint, fired on send outcome.
type Webhook struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret"`
}

// Client is a per-client API key and its metadata. AllowedFrom optionally
// restricts the from addresses the client may send from (empty = any
// allowlisted account).
type Client struct {
	Name        string   `json:"name"`
	Key         string   `json:"key"` // generated, stored hashed
	Note        string   `json:"note"`
	AllowedFrom []string `json:"allowed_from,omitempty"`
}

// OIDC is the Zitadel integration for human admin access.
type OIDC struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	AdminRole    string   `json:"admin_role"`
	RedirectURL  string   `json:"redirect_url"`
}

// Queue is the asynchronous send queue tuning.
type Queue struct {
	Enabled    bool   `json:"enabled"`              // async send path (default off)
	Workers    int    `json:"workers"`              // worker pool size
	Batch      int    `json:"batch"`                // jobs claimed per worker per round
	MaxSize    int    `json:"max_size"`             // max queued jobs (0 = unlimited)
	MaxRetries int    `json:"max_retries"`          // retries per job before dead
	RetryBase  int    `json:"retry_base"`           // initial backoff (seconds)
	DBPath     string `json:"db_path"`              // queue sqlite path
}

// Config is the full router configuration.
type Config struct {
	Providers  []Provider          `json:"providers"`
	Accounts   map[string]Account  `json:"accounts"`
	Allowlist  []string            `json:"allowlist"`
	Denylist   []string            `json:"denylist"`
	Clients    map[string]Client   `json:"clients"`
	Webhooks   []Webhook           `json:"webhooks"`
	OIDC       *OIDC               `json:"oidc,omitempty"`
	AdminToken string              `json:"admin_token,omitempty"`
	// DefaultRate applies when an account has no explicit Rate.
	DefaultRate Rate  `json:"default_rate"`
	Queue       Queue `json:"queue,omitempty"`
}

// Load reads the config from a JSON file at path. If path is empty it looks
// for a JSON config at $SMTP_ROUTER_CONFIG. Values may also be supplied via
// environment variables (SMTP_ROUTER_*), which override file values.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if path == "" {
		path = os.Getenv("SMTP_ROUTER_CONFIG")
	}
	if path != "" {
		// #nosec G703,G304 -- path comes from the -config CLI flag or
		// SMTP_ROUTER_CONFIG env, not from HTTP input. No untrusted traversal.
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(cfg)
	if cfg.DefaultRate.Day == 0 && cfg.DefaultRate.Month == 0 {
		cfg.DefaultRate = Rate{Day: 200, Month: 2000}
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SMTP_ROUTER_ADMIN_TOKEN"); v != "" {
		cfg.AdminToken = v
	}
	if v := os.Getenv("SMTP_ROUTER_DEFAULT_DAY"); v != "" {
		cfg.DefaultRate.Day = atoi(v)
	}
	if v := os.Getenv("SMTP_ROUTER_DEFAULT_MONTH"); v != "" {
		cfg.DefaultRate.Month = atoi(v)
	}
}

func atoi(s string) int {
	n := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		return -n
	}
	return n
}

// Validate checks required configuration. It returns an error when the
// config is unusable — e.g. no admin token (which would fail-open the admin
// API), no providers, or no accounts.
func (c *Config) Validate() error {
	if c.AdminToken == "" {
		return fmt.Errorf("admin_token is required: set admin_token (or SMTP_ROUTER_ADMIN_TOKEN) or admin access fails open")
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("no providers configured")
	}
	if len(c.Accounts) == 0 {
		return fmt.Errorf("no accounts configured")
	}
	for _, p := range c.Providers {
		switch p.Type {
		case "smtp":
			if p.Host == "" {
				return fmt.Errorf("provider %q: smtp host required", p.Name)
			}
		case "api":
			if p.URL == "" {
				return fmt.Errorf("provider %q: api url required", p.Name)
			}
		default:
			return fmt.Errorf("provider %q: unsupported type %q", p.Name, p.Type)
		}
	}
	// Allocation entries must reference configured providers.
	for from, a := range c.Accounts {
		for _, e := range a.Allocation {
			if e.Name == "" {
				return fmt.Errorf("account %q: allocation entry with empty provider name", from)
			}
			if c.ProviderNamed(e.Name) == nil {
				return fmt.Errorf("account %q: allocation references unknown provider %q", from, e.Name)
			}
		}
	}
	return nil
}

// Save writes the config back to the file at path (used by admin mutations so
// changes survive restart).
func (c *Config) Save(path string) error {
	if path == "" {
		return fmt.Errorf("no config path to save")
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// Atomic write: create a temp file in the same directory, write+fsync it,
	// then rename over the target. A crash mid-write leaves the old config
	// intact instead of a truncated/corrupt config.json (the only copy of
	// provider creds and admin settings).
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}

// LookupAccount resolves a from address to its account config, returning the
// account and whether it exists.
func (c *Config) LookupAccount(from string) (Account, bool) {
	if a, ok := c.Accounts[from]; ok {
		return a, true
	}
	return Account{}, false
}

// ProviderNamed returns the named provider, or nil.
func (c *Config) ProviderNamed(name string) *Provider {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

// Normalize trims whitespace from allowlist/denylist entries.
func (c *Config) Normalize() {
	for i := range c.Allowlist {
		c.Allowlist[i] = strings.TrimSpace(c.Allowlist[i])
	}
	for i := range c.Denylist {
		c.Denylist[i] = strings.TrimSpace(c.Denylist[i])
	}
}

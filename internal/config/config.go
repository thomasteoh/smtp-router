// Package config loads the email-router configuration from an environment
// file or YAML. It defines the providers, accounts, rate limits, rules,
// clients (API keys), webhooks, and OIDC settings the router operates with.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Provider is an upstream delivery provider: either SMTP (host/port/auth) or
// an HTTP API (url/token/method).
type Provider struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // "smtp" or "api"
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Auth   string `json:"auth"` // SMTP username:password or API token
	URL    string `json:"url"`
	Token  string `json:"token"`
	Method string `json:"method"`
}

// Rate is a per-account quota. Day and Month are independent counters so a
// provider's different restrictions can be accommodated.
type Rate struct {
	Day   int `json:"day"`
	Month int `json:"month"`
}

// Account is a sending account (a `from` address) plus its provider routing
// and per-account rate limits.
type Account struct {
	From     string `json:"from"`
	Provider string `json:"provider"`
	Rate     Rate   `json:"rate"`
}

// Webhook is an outgoing notification endpoint, fired on send outcome.
type Webhook struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret"`
}

// Client is a per-client API key and its metadata.
type Client struct {
	Name  string `json:"name"`
	Key   string `json:"key"` // generated, stored hashed
	Note  string `json:"note"`
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
	DefaultRate Rate `json:"default_rate"`
}

// Load reads the config from a JSON file at path. If path is empty it looks
// for a JSON config at $EMAIL_ROUTER_CONFIG. Values may also be supplied via
// environment variables (EMAIL_ROUTER_*), which override file values.
func Load(path string) (*Config, error) {
	cfg := &Config{}
	if path == "" {
		path = os.Getenv("EMAIL_ROUTER_CONFIG")
	}
	if path != "" {
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
	if v := os.Getenv("EMAIL_ROUTER_ADMIN_TOKEN"); v != "" {
		cfg.AdminToken = v
	}
	if v := os.Getenv("EMAIL_ROUTER_DEFAULT_DAY"); v != "" {
		cfg.DefaultRate.Day = atoi(v)
	}
	if v := os.Getenv("EMAIL_ROUTER_DEFAULT_MONTH"); v != "" {
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

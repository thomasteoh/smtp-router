// Package oidc integrates the smtp-router with Zitadel for human admin
// access. It verifies ID tokens from the configured OIDC issuer and gates
// admin routes by a role claim.
package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier verifies OIDC ID tokens from a configured issuer.
type Verifier struct {
	mu     sync.Mutex
	prov   *oidc.Provider
	cfg    Config
}

// Config carries the OIDC settings.
type Config struct {
	Issuer       string
	ClientID     string
	Scopes       []string
	AdminRole    string
	RedirectURL  string
}

// New builds a Verifier with the given config.
func New(cfg Config) *Verifier {
	return &Verifier{cfg: cfg}
}

// Config returns the verifier's OIDC config (e.g. the admin role key).
func (v *Verifier) Config() Config {
	return v.cfg
}

// Verify checks an ID token's signature, issuer, and audience, then returns
// the claims and whether the token carries the admin role.
func (v *Verifier) Verify(ctx context.Context, raw string) (claims map[string]any, admin bool, err error) {
	p, err := v.provider(ctx)
	if err != nil {
		return nil, false, err
	}
	verifier := p.Verifier(&oidc.Config{ClientID: v.cfg.ClientID})
	idTok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, false, fmt.Errorf("verify id token: %w", err)
	}
	var c map[string]any
	if err := idTok.Claims(&c); err != nil {
		return nil, false, fmt.Errorf("read claims: %w", err)
	}
	admin = hasRole(c, v.cfg.AdminRole)
	return c, admin, nil
}

// provider lazily initialises the OIDC provider, caching on success.
func (v *Verifier) provider(ctx context.Context) (*oidc.Provider, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.prov != nil {
		return v.prov, nil
	}
	p, err := oidc.NewProvider(ctx, v.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	v.prov = p
	return p, nil
}

// hasRole checks a Zitadel-style roles claim. The claim shape is
// {"<roleKey>": {"<orgId>": "<domain>"}} — top-level keys are the role keys.
func hasRole(c map[string]any, role string) bool {
	if role == "" {
		return true
	}
	raw, ok := c["urn:zitadel:iam:org:project:roles"]
	if !ok {
		// fall back to a flat roles claim
		flat, ok := c["roles"].([]any)
		if !ok {
			return false
		}
		for _, r := range flat {
			if fmt.Sprint(r) == role {
				return true
			}
		}
		return false
	}
	roles, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	if _, ok := roles[role]; ok {
		return true
	}
	// Some issuers nest project-scoped roles; check any key equals the role.
	for k := range roles {
		if k == role {
			return true
		}
	}
	return false
}

// Package portal implements the smtp-router admin web portal. It adds an
// OIDC Connect authorization-code login flow (login -> authorize -> callback
// -> token exchange -> session) and serves an embedded HTML admin console
// that drives the existing token-gated admin API using the session's ID token.
package portal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thomasteoh/smtp-router/web"
	"golang.org/x/oauth2"
)

// Config carries the OIDC settings needed to drive the login flow.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	AdminRole    string
	RedirectURL  string
}

// session is a signed-in admin session. The access token is stored so the
// portal can present it as a Bearer credential to the admin API on the user's
// behalf. The ID token is kept for the role check at login; the access token
// is what the admin API re-verifies on each call (it lives longer and is
// refreshable, so it does not expire mid-session like a 1h ID token would).
type session struct {
	idToken     string
	accessToken string
	email       string
	name        string
	roles       []string
	expiry      time.Time
}

// Verifier is the minimal OIDC ID-token verifier the portal needs. It verifies
// a raw ID token and reports whether the user holds the admin role.
type Verifier interface {
	Verify(ctx context.Context, raw string) (claims map[string]any, admin bool, err error)
}

// Portal is the admin web UI server.
type Portal struct {
	oauth        *oauth2.Config
	verifier     Verifier
	adminRole    string
	issuer       string
	redirectURL  string
	// exchange performs the OIDC token exchange. Defaults to oauth.Config.Exchange;
	// injectable for tests.
	exchange func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)

	mu       sync.Mutex
	sessions map[string]session
	states   map[string]string // state -> "" (single-use)
}

// New builds a Portal from the OIDC settings. The verifier is the router's own
// verifier, so the same admin-role claim check applies to the web login.
func New(cfg Config, verifier Verifier) *Portal {
	if len(cfg.Scopes) == 0 {
		// "openid profile email" alone does NOT make Zitadel assert the roles
		// claim; Zitadel only includes urn:zitadel:iam:org:project:roles when a
		// role scope is requested (urn:zitadel:iam:org:projects:roles asserts
		// all the user's grants' roles). Without it the admin-role check fails
		// and the portal returns "forbidden: admin role required".
		cfg.Scopes = []string{"openid", "profile", "email", "urn:zitadel:iam:org:projects:roles"}
	}
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.Issuer + "/oauth/v2/authorize",
			TokenURL: cfg.Issuer + "/oauth/v2/token",
		},
	}
	return &Portal{
		oauth:        oc,
		verifier:     verifier,
		adminRole:    cfg.AdminRole,
		issuer:       cfg.Issuer,
		redirectURL:  cfg.RedirectURL,
		exchange:     oc.Exchange,
		sessions:     map[string]session{},
		states:       map[string]string{},
	}
}

// Handler returns the portal HTTP handler.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.handlePortal)
	mux.HandleFunc("GET /login", p.handleLogin)
	mux.HandleFunc("GET /callback", p.handleCallback)
	mux.HandleFunc("GET /logout", p.handleLogout)
	return mux
}

// Register adds the portal's routes to an existing ServeMux.
func (p *Portal) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", p.handlePortal)
	mux.HandleFunc("GET /login", p.handleLogin)
	mux.HandleFunc("GET /callback", p.handleCallback)
	mux.HandleFunc("GET /logout", p.handleLogout)
}

// handlePortal serves the admin console at the site root, or redirects to
// /login when no valid session cookie is present.
func (p *Portal) handlePortal(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("smtp_router_sess")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	p.mu.Lock()
	sess, ok := p.sessions[cookie.Value]
	p.mu.Unlock()
	if !ok || time.Now().After(sess.expiry) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Email       string
		Name        string
		Roles       []string
		AccessToken string
	}{
		Email:       sess.email,
		Name:        sess.name,
		Roles:       sess.roles,
		AccessToken: sess.accessToken,
	}
	page := template.Must(template.New("index").Parse(string(web.IndexHTML())))
	if err := page.ExecuteTemplate(w, "index", data); err != nil {
		log.Printf("portal render: %v", err)
	}
}

// handleLogin kicks off the Zitadel OIDC authorization code flow.
func (p *Portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randomToken(16)
	p.mu.Lock()
	p.states[state] = ""
	// Cap stale states so abandoned logins don't accumulate.
	const maxStates = 512
	if len(p.states) > maxStates {
		for k := range p.states {
			if len(p.states) <= maxStates {
				break
			}
			delete(p.states, k)
		}
	}
	p.mu.Unlock()
	// prompt=login forces a fresh Zitadel login on every visit to /login, so
	// after a logout the user isn't silently re-authenticated from Zitadel's
	// persisted session (that's what made logout appear to "not work").
	url := p.oauth.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("prompt", "login"))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback exchanges the authorization code, verifies the ID token via
// the router's OIDC verifier, checks the admin role, and establishes a session.
func (p *Portal) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	_, ok := p.states[state]
	delete(p.states, state)
	p.mu.Unlock()
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := p.exchange(ctx, code)
	if err != nil {
		log.Printf("token exchange: %v", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		http.Error(w, "id_token missing", http.StatusInternalServerError)
		return
	}
	// Keep the access token too: the admin API re-verifies the Bearer on every
	// call, and the ID token expires quickly (~1h) while the session lasts 12h.
	// Using the access token avoids 401s mid-session. Zitadel access tokens
	// carry the same role claim (access_token_role_assertion=true).
	access := tok.AccessToken
	claims, admin, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		log.Printf("id token verify: %v", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	if !admin {
		log.Printf("user lacks %q role", p.adminRole)
		http.Error(w, "forbidden: admin role required", http.StatusForbidden)
		return
	}

	tokID := randomToken(32)
	p.mu.Lock()
	p.sessions[tokID] = session{
		idToken:     raw,
		accessToken: access,
		email:       claimString(claims, "email"),
		name:        claimString(claims, "name"),
		roles:       roleKeys(claims),
		expiry:      time.Now().Add(12 * time.Hour),
	}
	// Sweep expired sessions.
	now := time.Now()
	for k, v := range p.sessions {
		if now.After(v.expiry) {
			delete(p.sessions, k)
		}
	}
	p.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "smtp_router_sess",
		Value:    tokID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   12 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session cookie and drops the stored session, then
// redirects to Zitadel's RP-initiated logout so the IdP session is also ended
// (without this the browser is silently re-authenticated on the next /login).
func (p *Portal) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idHint string
	if cookie, err := r.Cookie("smtp_router_sess"); err == nil {
		p.mu.Lock()
		if s, ok := p.sessions[cookie.Value]; ok {
			idHint = s.idToken
		}
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "smtp_router_sess",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	// Idempotent logout: if there is no session (already logged out, e.g. the
	// browser returned here from Zitadel's post_logout_redirect_uri), redirect
	// to the site root instead of looping back to end_session. Without this the
	// second /logout call sends an empty id_token_hint, Zitadel rejects it and
	// bounces to its own UI logout page — "logout doesn't redirect properly".
	if idHint == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// RP-initiated logout: hit Zitadel's end_session_endpoint with the ID token
	// and a post-logout redirect back to the portal (which then forces fresh
	// login via prompt=login).
	q := url.Values{}
	q.Set("id_token_hint", idHint)
	// post_logout_redirect_uri must point back at the portal's /logout (site
	// root), not the OIDC /callback. Derive the site base from redirectURL by
	// stripping the /callback suffix, then append /logout. TrimSuffix is safe
	// even when the suffix is absent (returns the string unchanged).
	site := strings.TrimSuffix(p.redirectURL, "/callback")
	q.Set("post_logout_redirect_uri", site+"/logout")
	http.Redirect(w, r, p.issuer+"/oidc/v1/end_session?"+q.Encode(), http.StatusFound)
}

// claimString returns a string claim value, or "".
func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// roleKeys extracts Zitadel role keys from the roles claim.
func roleKeys(claims map[string]any) []string {
	var roles []string
	raw, ok := claims["urn:zitadel:iam:org:project:roles"]
	if ok {
		if m, ok := raw.(map[string]any); ok {
			for k := range m {
				roles = append(roles, k)
			}
		}
	}
	if len(roles) == 0 {
		if arr, ok := claims["roles"].([]any); ok {
			for _, r := range arr {
				roles = append(roles, fmt.Sprint(r))
			}
		}
	}
	return unique(roles)
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

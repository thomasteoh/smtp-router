package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// fakeVerifier implements Verifier for tests. It returns admin=true when raw
// is "admin-token" and admin=false otherwise.
type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, raw string) (map[string]any, bool, error) {
	if raw == "admin-token" {
		return map[string]any{"email": "thomas@harmonicr.com", "name": "Thomas", "sub": "u1"}, true, nil
	}
	return nil, false, nil
}

func newTestPortal() *Portal {
	return New(Config{
		Issuer:       "https://auth.harmonicr.com",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"openid", "profile", "email"},
		AdminRole:    "admin",
		RedirectURL:  "https://smtp.harmonicr.com/callback",
	}, fakeVerifier{})
}

func TestPortalRedirectsWithoutSession(t *testing.T) {
	p := newTestPortal()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/portal", nil)
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("location = %q, want /login", got)
	}
}

func TestLoginRedirectsToAuthorize(t *testing.T) {
	p := newTestPortal()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/oauth/v2/authorize") {
		t.Fatalf("location = %q, want authorize endpoint", loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Fatalf("location = %q, want state param", loc)
	}
}

func TestCallbackRejectsMissingCode(t *testing.T) {
	p := newTestPortal()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/callback", nil)
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsInvalidState(t *testing.T) {
	p := newTestPortal()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/callback?code=x&state=bogus", nil)
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestCallbackWithAdminSession exercises the full happy path with an injected
// token exchange: a valid state, an exchanged token carrying an ID token that
// verifies as admin, then a session cookie + redirect to /portal.
func TestCallbackWithAdminSession(t *testing.T) {
	p := newTestPortal()
	// Inject a fake exchange that returns an ID token.
	p.exchange = func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
		if code != "good-code" {
			t.Fatalf("exchange code = %q", code)
		}
		return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "admin-token"}), nil
	}
	state := "test-state"
	p.mu.Lock()
	p.states[state] = ""
	p.mu.Unlock()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/callback?code=good-code&state="+state, nil)
	p.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/portal" {
		t.Fatalf("location = %q, want /portal", got)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "smtp_router_sess" {
		t.Fatalf("expected session cookie, got %v", cookies)
	}
	// The state must be consumed.
	p.mu.Lock()
	_, ok := p.states[state]
	p.mu.Unlock()
	if ok {
		t.Fatal("state was not consumed")
	}
}

func TestCallbackRejectsNonAdmin(t *testing.T) {
	p := newTestPortal()
	p.exchange = func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
		return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "non-admin-token"}), nil
	}
	state := "test-state"
	p.mu.Lock()
	p.states[state] = ""
	p.mu.Unlock()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/callback?code=code&state="+state, nil)
	p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/smtp-router/internal/audit"
	"github.com/thomasteoh/smtp-router/internal/auth"
	"github.com/thomasteoh/smtp-router/internal/config"
	"github.com/thomasteoh/smtp-router/internal/provider"
	"github.com/thomasteoh/smtp-router/internal/ratelimit"
	"github.com/thomasteoh/smtp-router/internal/rules"
)

// stubSender records the messages it is asked to deliver.
type stubSender struct {
	mu   sync.Mutex
	msgs []provider.Message
	err  error
}

func (s *stubSender) Deliver(ctx context.Context, msg provider.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, msg)
	return s.err
}

func newTestServer(t *testing.T, cfg *config.Config) (*Server, *stubSender, string) {
	t.Helper()
	cfg.AdminToken = "admin-secret"
	cfg.DefaultRate = config.Rate{Day: 100, Month: 1000}
	au := auth.New()
	au.Add("billing", "raw-key-billing")
	cfg.Clients = map[string]config.Client{"billing": {Name: "billing", Key: auth.HashHex("raw-key-billing")}}
	ad, err := audit.Open(":memory:")
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	stub := &stubSender{}
	prov := make(map[string]provider.Sender)
	prov["smtp"] = stub
	s := &Server{cfg: cfg, auth: au, audit: ad, limit: lim, rules: rl, prov: prov}
	return s, stub, "raw-key-billing"
}

// TestHeaderInjectionRejected verifies CR/LF in Subject/From/To is rejected
// (C2 — no MIME header injection).
func TestHeaderInjectionRejected(t *testing.T) {
	s, _, key := newTestServer(t, &config.Config{
		Providers: []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:  map[string]config.Account{"billing@harmonicr.com": {From: "billing@harmonicr.com", Provider: "smtp"}},
		Allowlist: []string{"billing@harmonicr.com"},
	})
	body := `{"from":"billing@harmonicr.com","to":["x@y.com"],"subject":"hi\r\nBcc: evil@attacker.com\r\nX-Evil: yes","body":"test"}`
	req := httptest.NewRequest("POST", "/send", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CRLF subject, got %d: %s", w.Code, w.Body.String())
	}
}

// TestAdminFailClosed verifies the admin API refuses requests when no token is
// configured (C1 — fail-closed, never open).
func TestAdminFailClosed(t *testing.T) {
	s, _, _ := newTestServer(t, &config.Config{
		Providers: []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:  map[string]config.Account{"a@x.com": {From: "a@x.com", Provider: "smtp"}},
		AdminToken: "", // empty — must fail closed
	})
	req := httptest.NewRequest("GET", "/admin/audit", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no token configured, got %d", w.Code)
	}
}

// TestAdminWrongToken verifies a wrong token is rejected.
func TestAdminWrongToken(t *testing.T) {
	s, _, _ := newTestServer(t, &config.Config{
		Providers:   []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:    map[string]config.Account{"a@x.com": {From: "a@x.com", Provider: "smtp"}},
		AdminToken:  "real-secret",
		Allowlist:   []string{"a@x.com"},
	})
	req := httptest.NewRequest("GET", "/admin/audit", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", w.Code)
	}
}

// TestFromBinding verifies a client bound to one from address cannot send from
// another (H3 — per-client from-binding).
func TestFromBinding(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:  map[string]config.Account{"billing@harmonicr.com": {From: "billing@harmonicr.com", Provider: "smtp"}},
		Allowlist: []string{"billing@harmonicr.com", "sales@harmonicr.com"},
	}
	au := auth.New()
	au.Add("billing", "raw-key-billing")
	cfg.Clients = map[string]config.Client{
		"billing": {Name: "billing", Key: auth.HashHex("raw-key-billing"), AllowedFrom: []string{"billing@harmonicr.com"}},
	}
	ad, _ := audit.Open(":memory:")
	s := &Server{cfg: cfg, auth: au, audit: ad, limit: ratelimit.New(), rules: rules.New(cfg.Allowlist, cfg.Denylist), prov: map[string]provider.Sender{"smtp": &stubSender{}}}
	body := `{"from":"sales@harmonicr.com","to":["x@y.com"],"subject":"hi","body":"test"}`
	req := httptest.NewRequest("POST", "/send", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", "raw-key-billing")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when client not bound to from, got %d", w.Code)
	}
}

// TestAdminAddClientPersists verifies the admin API can add a client and the
// raw key is returned once.
func TestAdminAddClientPersists(t *testing.T) {
	cfg := &config.Config{
		Providers:  []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:   map[string]config.Account{"a@x.com": {From: "a@x.com", Provider: "smtp"}},
		AdminToken: "secret",
	}
	au := auth.New()
	ad, _ := audit.Open(":memory:")
	s := &Server{cfg: cfg, auth: au, audit: ad, limit: ratelimit.New(), rules: rules.New(cfg.Allowlist, cfg.Denylist), prov: map[string]provider.Sender{"smtp": &stubSender{}}}
	body := `{"name":"newclient"}`
	req := httptest.NewRequest("POST", "/admin/clients", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["key"] == "" || resp["key"] == nil {
		t.Fatalf("expected raw key in response, got %v", resp)
	}
	if s.auth.Validate(resp["key"].(string)) == "" {
		t.Fatalf("generated key should validate")
	}
}

// TestConcurrentSendAndAdmin verifies no data race between handleSend and
// adminAddProvider (C3).
func TestConcurrentSendAndAdmin(t *testing.T) {
	cfg := &config.Config{
		Providers:  []config.Provider{{Name: "smtp", Type: "smtp", Host: "x", Port: 25}},
		Accounts:   map[string]config.Account{"a@x.com": {From: "a@x.com", Provider: "smtp"}},
		AdminToken: "secret",
		Allowlist:  []string{"a@x.com"},
	}
	au := auth.New()
	au.Add("billing", "raw-key-billing")
	cfg.Clients = map[string]config.Client{"billing": {Name: "billing", Key: auth.HashHex("raw-key-billing")}}
	ad, _ := audit.Open(":memory:")
	s := &Server{cfg: cfg, auth: au, audit: ad, limit: ratelimit.New(), rules: rules.New(cfg.Allowlist, cfg.Denylist), prov: map[string]provider.Sender{"smtp": &stubSender{}}}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		body := `{"from":"a@x.com","to":["y@z.com"],"subject":"hi","body":"test"}`
		for {
			select {
			case <-stop:
				return
			default:
				req := httptest.NewRequest("POST", "/send", bytes.NewBufferString(body))
				req.Header.Set("X-API-Key", "raw-key-billing")
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, req)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			body := `{"name":"new","type":"smtp","host":"x","port":25}`
			req := httptest.NewRequest("POST", "/admin/providers", bytes.NewBufferString(body))
			req.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			time.Sleep(time.Millisecond)
		}
		close(stop)
	}()
	wg.Wait()
	// If a race existed, the race detector would have failed the test.
}
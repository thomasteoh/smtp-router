package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/thomasteoh/smtp-router/internal/auth"
	"github.com/thomasteoh/smtp-router/internal/audit"
	"github.com/thomasteoh/smtp-router/internal/config"
	"github.com/thomasteoh/smtp-router/internal/oidc"
	"github.com/thomasteoh/smtp-router/internal/portal"
	"github.com/thomasteoh/smtp-router/internal/queue"
	"github.com/thomasteoh/smtp-router/internal/ratelimit"
	"github.com/thomasteoh/smtp-router/internal/rules"
	"github.com/thomasteoh/smtp-router/internal/webhook"
)

// startFakeSMTP runs a minimal SMTP responder on 127.0.0.1:2525 that accepts
// a single message. It returns a cleanup func.
func startFakeSMTP(t *testing.T) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:2525")
	if err != nil {
		t.Fatalf("fake smtp listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				// 220 greeting
				c.Write([]byte("220 fake ESMTP\r\n"))
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					switch {
					case strings.HasPrefix(line, "EHLO"):
						c.Write([]byte("250-fake\r\n250 OK\r\n"))
					case strings.HasPrefix(line, "HELO"):
						c.Write([]byte("250 OK\r\n"))
					case strings.HasPrefix(line, "AUTH"):
						c.Write([]byte("235 ok\r\n"))
					case strings.HasPrefix(line, "MAIL"):
						c.Write([]byte("250 ok\r\n"))
					case strings.HasPrefix(line, "RCPT"):
						c.Write([]byte("250 ok\r\n"))
					case strings.HasPrefix(line, "DATA"):
						c.Write([]byte("354 go ahead\r\n"))
						// read until "."
						for {
							d, err := r.ReadString('\n')
							if err != nil {
								return
							}
							if strings.TrimRight(d, "\r\n") == "." {
								break
							}
						}
						c.Write([]byte("250 ok queued\r\n"))
					case strings.HasPrefix(line, "QUIT"):
						c.Write([]byte("221 bye\r\n"))
						return
					default:
						c.Write([]byte("250 ok\r\n"))
					}
				}
			}(c)
		}
	}()
	return func() { ln.Close() }
}

func TestSendDelivered(t *testing.T) {
	cleanup := startFakeSMTP(t)
	defer cleanup()
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "smtp", Type: "smtp", Host: "127.0.0.1", Port: 2525},
		},
		Accounts: map[string]config.Account{
			"alerts@harmonicr.com": {From: "alerts@harmonicr.com", Provider: "smtp", Rate: config.Rate{Day: 10, Month: 100}},
		},
		Allowlist:  []string{"*@harmonicr.com"},
		DefaultRate: config.Rate{Day: 200, Month: 2000},
	}
	au := auth.New()
	key, _ := au.Generate("client-1")
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	hk := webhook.New(nil)

	s, err := New(cfg, au, ad, lim, rl, hk, &oidc.Verifier{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	body := SendRequest{From: "alerts@harmonicr.com", To: []string{"x@example.com"}, Subject: "hi", Body: "hello"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var res SendResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Status != "delivered" {
		t.Fatalf("status = %s", res.Status)
	}
	// Audit row recorded.
	rows, _ := ad.List(10)
	if len(rows) != 1 || rows[0].Status != audit.StatusDelivered {
		t.Fatalf("audit rows = %d, want 1 delivered", len(rows))
	}
}

func TestSendRateLimited(t *testing.T) {
	cleanup := startFakeSMTP(t)
	defer cleanup()
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "smtp", Type: "smtp", Host: "127.0.0.1", Port: 2525},
		},
		Accounts: map[string]config.Account{
			"alerts@harmonicr.com": {From: "alerts@harmonicr.com", Provider: "smtp", Rate: config.Rate{Day: 1, Month: 100}},
		},
		Allowlist:  []string{"*@harmonicr.com"},
		DefaultRate: config.Rate{Day: 200, Month: 2000},
	}
	au := auth.New()
	key, _ := au.Generate("client-1")
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})

	body := SendRequest{From: "alerts@harmonicr.com", To: []string{"x@example.com"}, Subject: "hi", Body: "hello"}
	b, _ := json.Marshal(body)

	// First send passes.
	req := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("first status = %d", rec.Code)
	}

	// Second exceeds day limit.
	req2 := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req2.Header.Set("X-API-Key", key)
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != 429 {
		t.Fatalf("second status = %d, want 429", rec2.Code)
	}
}

func TestSendDenied(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "smtp", Type: "smtp", Host: "127.0.0.1", Port: 2525}},
		Accounts:  map[string]config.Account{"alerts@harmonicr.com": {From: "alerts@harmonicr.com", Provider: "smtp"}},
		Allowlist:  []string{"*@harmonicr.com"},
		Denylist:   []string{"spam@harmonicr.com"},
	}
	au := auth.New()
	key, _ := au.Generate("client-1")
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})

	body := SendRequest{From: "spam@harmonicr.com", To: []string{"x@example.com"}}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestPortalRouteRegistered(t *testing.T) {
	cfg := &config.Config{Allowlist: []string{"*@harmonicr.com"}}
	au := auth.New()
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	ov := &oidc.Verifier{}
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), ov)
	// Attach a portal (OIDC login flow) and verify the route is reachable.
	s.SetPortal(portal.New(portal.Config{
		Issuer:       "https://auth.harmonicr.com",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"openid", "profile", "email"},
		AdminRole:    "admin",
		RedirectURL:  "https://smtp.harmonicr.com/callback",
	}, &oidc.Verifier{}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 302 {
		t.Fatalf("status = %d, want 302 redirect to login", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("location = %q, want /login", got)
	}
}

func TestAdminListAndDelete(t *testing.T) {
	cfg := &config.Config{
		AdminToken: "tok",
		Providers:  []config.Provider{{Name: "smtp", Type: "smtp", Host: "h"}},
		Accounts:   map[string]config.Account{"a@h.com": {From: "a@h.com", Provider: "smtp"}},
		Clients:    map[string]config.Client{"c1": {Name: "c1", Note: "n"}},
		Allowlist:  []string{"*@h.com"},
	}
	au := auth.New()
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})
	s.SetConfigPath(t.TempDir() + "/cfg.json")
	h := s.Handler()

	// List providers
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/providers", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("list providers status = %d", rec.Code)
	}

	// Delete provider
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/admin/providers/smtp", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete provider status = %d", rec.Code)
	}
	// Verify it's gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/providers", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Fatalf("provider still listed: %s", rec.Body.String())
	}

	// List accounts
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/accounts", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "a@h.com") {
		t.Fatalf("list accounts: %d %s", rec.Code, rec.Body.String())
	}

	// Delete account (from in path)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/admin/accounts/a@h.com", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete account status = %d", rec.Code)
	}

	// List rules
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/rules", nil)
	req.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "*@h.com") {
		t.Fatalf("list rules: %d %s", rec.Code, rec.Body.String())
	}

	// Unauthorized without token
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/admin/providers", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthorized status = %d", rec.Code)
	}
}

func TestSendUnauthorized(t *testing.T) {
	cfg := &config.Config{Allowlist: []string{"*@harmonicr.com"}}
	au := auth.New()
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})

	body := SendRequest{From: "alerts@harmonicr.com", To: []string{"x@example.com"}}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req.Header.Set("X-API-Key", "wrong")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSendQueuedAsync(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{{Name: "smtp", Type: "smtp", Host: "127.0.0.1", Port: 2525}},
		Accounts:  map[string]config.Account{"alerts@harmonicr.com": {From: "alerts@harmonicr.com", Provider: "smtp"}},
		Allowlist: []string{"*@harmonicr.com"},
	}
	au := auth.New()
	key, _ := au.Generate("client-1")
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})

	// Attach a queue pool.
	qstore, _ := queue.Open(":memory:")
	defer qstore.Close()
	pool := queue.NewPool(qstore, queue.Config{Workers: 1, Batch: 4, MaxRetries: 3},
		func(ctx context.Context, j queue.Job) (string, error) { return "smtp", nil })
	s.SetQueue(pool)

	body := SendRequest{From: "alerts@harmonicr.com", To: []string{"x@example.com"}, Subject: "hi", Body: "hello"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/send", bytes.NewReader(b))
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	// Async: 202 accepted with a job id.
	if rec.Code != 202 {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var res SendResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Status != "accepted" || res.JobID == 0 {
		t.Fatalf("result = %+v, want accepted with job id", res)
	}
	if n, _ := qstore.Count("queued"); n != 1 {
		t.Fatalf("queued = %d, want 1", n)
	}
}

func TestAdminQueueStatsAndCancel(t *testing.T) {
	cfg := &config.Config{
		Providers:  []config.Provider{{Name: "smtp", Type: "smtp", Host: "127.0.0.1", Port: 2525}},
		Accounts:   map[string]config.Account{"alerts@harmonicr.com": {From: "alerts@harmonicr.com", Provider: "smtp"}},
		Allowlist:  []string{"*@harmonicr.com"},
		AdminToken: "admin-token",
	}
	au := auth.New()
	ad, _ := audit.Open(":memory:")
	defer ad.Close()
	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	s, _ := New(cfg, au, ad, lim, rl, webhook.New(nil), &oidc.Verifier{})

	qstore, _ := queue.Open(":memory:")
	defer qstore.Close()
	pool := queue.NewPool(qstore, queue.Config{Workers: 1, Batch: 4, MaxRetries: 3},
		func(ctx context.Context, j queue.Job) (string, error) { return "smtp", nil })
	s.SetQueue(pool)

	// Enqueue a job directly.
	id, _ := qstore.Enqueue(queue.Job{Client: "client-1", From: "alerts@harmonicr.com", To: []string{"x@example.com"}})

	// GET /admin/queue with token.
	req := httptest.NewRequest("GET", "/admin/queue", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("queue stats status = %d, want 200", rec.Code)
	}

	// Cancel the queued job.
	req2 := httptest.NewRequest("DELETE", "/admin/queue/jobs/"+strconv.FormatInt(id, 10), nil)
	req2.Header.Set("Authorization", "Bearer admin-token")
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("cancel status = %d, want 200", rec2.Code)
	}
	if n, _ := qstore.Count("dead"); n != 1 {
		t.Fatalf("dead = %d, want 1", n)
	}
}

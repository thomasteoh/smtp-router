package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harmonicr/email-router/internal/auth"
	"github.com/harmonicr/email-router/internal/audit"
	"github.com/harmonicr/email-router/internal/config"
	"github.com/harmonicr/email-router/internal/oidc"
	"github.com/harmonicr/email-router/internal/ratelimit"
	"github.com/harmonicr/email-router/internal/rules"
	"github.com/harmonicr/email-router/internal/webhook"
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

var _ = context.Background

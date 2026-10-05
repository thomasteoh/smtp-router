// Package server exposes the smtp-router HTTP API: the send endpoint and
// token-gated admin endpoints, plus health/readiness.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/thomasteoh/smtp-router/internal/auth"
	"github.com/thomasteoh/smtp-router/internal/audit"
	"github.com/thomasteoh/smtp-router/internal/config"
	"github.com/thomasteoh/smtp-router/internal/oidc"
	"github.com/thomasteoh/smtp-router/internal/provider"
	"github.com/thomasteoh/smtp-router/internal/ratelimit"
	"github.com/thomasteoh/smtp-router/internal/rules"
	"github.com/thomasteoh/smtp-router/internal/webhook"
)

// Server is the HTTP API server.
type Server struct {
	cfg     *config.Config
	auth    *auth.Auth
	audit   *audit.Store
	limit   *ratelimit.Limiter
	rules   *rules.Rules
	hook    *webhook.Dispatcher
	oidc    *oidc.Verifier
	prov    map[string]provider.Sender
}

// New builds a Server. It wires providers from the config.
func New(cfg *config.Config, au *auth.Auth, ad *audit.Store, lim *ratelimit.Limiter, rl *rules.Rules, hk *webhook.Dispatcher, ov *oidc.Verifier) (*Server, error) {
	prov := make(map[string]provider.Sender)
	for _, p := range cfg.Providers {
		s, err := provider.New(p)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", p.Name, err)
		}
		prov[p.Name] = s
	}
	return &Server{cfg: cfg, auth: au, audit: ad, limit: lim, rules: rl, hook: hk, oidc: ov, prov: prov}, nil
}

// Handler returns the http.Handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /send", s.handleSend)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)

	// Admin endpoints (token-gated).
	mux.HandleFunc("POST /admin/providers", s.gateAdmin(s.adminAddProvider))
	mux.HandleFunc("GET /admin/audit", s.gateAdmin(s.adminListAudit))
	mux.HandleFunc("GET /admin/usage", s.gateAdmin(s.adminUsage))
	return mux
}

// SendRequest is the JSON body for POST /send.
type SendRequest struct {
	RequestID   string   `json:"request_id"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	HTML        string   `json:"html"`
	Attachments []Attach `json:"attachments,omitempty"`
	Provider    string   `json:"provider"`
}

// Attach is an attachment entry.
type Attach struct {
	Filename    string `json:"filename"`
	ContentB64  string `json:"content_b64"`
	ContentType string `json:"content_type"`
}

// SendResult is the response for POST /send.
type SendResult struct {
	Status   string `json:"status"` // delivered | rate_limited | denied | error
	Provider string `json:"provider,omitempty"`
	Error    string `json:"error,omitempty"`
}

// handleSend processes a send request.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	// Caller auth via X-API-Key.
	key := r.Header.Get("X-API-Key")
	client := s.auth.Validate(key)
	if client == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req SendRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.From == "" || len(req.To) == 0 {
		http.Error(w, "from and to required", http.StatusBadRequest)
		return
	}

	// Sender rules (allow/deny).
	if err := s.rules.Check(req.From); err != nil {
		s.record(client, req, audit.StatusDenied, "", req.RequestID)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Resolve account + rate limits.
	acc, ok := s.cfg.LookupAccount(req.From)
	if !ok {
		http.Error(w, "account not configured", http.StatusForbidden)
		return
	}
	dayLimit, monthLimit := acc.Rate.Day, acc.Rate.Month
	if dayLimit == 0 && monthLimit == 0 {
		dayLimit, monthLimit = s.cfg.DefaultRate.Day, s.cfg.DefaultRate.Month
	}

	// Rate limit (day + month).
	if !s.limit.Allow(req.From, dayLimit, monthLimit) {
		s.record(client, req, audit.StatusRateLimited, "", req.RequestID)
		writeJSON(w, http.StatusTooManyRequests, SendResult{Status: audit.StatusRateLimited})
		return
	}

	// Pick provider.
	provName := req.Provider
	if provName == "" {
		provName = acc.Provider
	}
	if provName == "" {
		http.Error(w, "no provider for account", http.StatusBadRequest)
		return
	}
	sender, ok := s.prov[provName]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	// Deliver.
	msg := provider.Message{
		From:    req.From,
		To:      req.To,
		Subject: req.Subject,
		Body:    req.Body,
		HTML:    req.HTML,
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := sender.Deliver(ctx, msg); err != nil {
		s.record(client, req, audit.StatusError, err.Error(), req.RequestID)
		s.hook.Fire(r.Context(), webhook.EventError, map[string]any{
			"client": client, "from": req.From, "provider": provName, "error": err.Error(),
		})
		writeJSON(w, http.StatusInternalServerError, SendResult{Status: audit.StatusError, Provider: provName, Error: err.Error()})
		return
	}

	s.record(client, req, audit.StatusDelivered, "", req.RequestID)
	s.hook.Fire(r.Context(), webhook.EventDelivered, map[string]any{
		"client": client, "from": req.From, "provider": provName,
	})
	writeJSON(w, http.StatusOK, SendResult{Status: audit.StatusDelivered, Provider: provName})
}

// record writes an audit row for a send.
func (s *Server) record(client string, req SendRequest, status, errMsg, requestID string) {
	if s.audit == nil {
		return
	}
	provName := req.Provider
	acc, ok := s.cfg.LookupAccount(req.From)
	if ok && acc.Provider != "" {
		provName = acc.Provider
	}
	if err := s.audit.Record(client, req.From, provName, status, errMsg, requestID); err != nil {
		log.Printf("audit: %v", err)
	}
}

// handleHealth returns 200 when the server is up.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// gateAdmin wraps an admin handler with token auth.
func (s *Server) gateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Authorization")
		tok = strings.TrimPrefix(tok, "Bearer ")
		if s.cfg.AdminToken != "" && tok != s.cfg.AdminToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// adminAddProvider adds a provider (admin). It accepts a provider JSON body.
func (s *Server) adminAddProvider(w http.ResponseWriter, r *http.Request) {
	var p config.Provider
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sender, err := provider.New(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Providers = append(s.cfg.Providers, p)
	s.prov[p.Name] = sender
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": p.Name})
}

// adminListAudit lists recent audit rows.
func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	n := 0
	fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n)
	rows, err := s.audit.List(n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// adminUsage returns per-account usage counters.
func (s *Server) adminUsage(w http.ResponseWriter, r *http.Request) {
	accounts := make(map[string]map[string]int)
	for name := range s.cfg.Accounts {
		d, m := s.limit.Usage(name)
		accounts[name] = map[string]int{"day": d, "month": m}
	}
	writeJSON(w, http.StatusOK, accounts)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

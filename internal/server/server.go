// Package server exposes the smtp-router HTTP API: the send endpoint and
// token/OIDC-gated admin endpoints, plus health/readiness and metrics.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thomasteoh/smtp-router/internal/auth"
	"github.com/thomasteoh/smtp-router/internal/audit"
	"github.com/thomasteoh/smtp-router/internal/config"
	"github.com/thomasteoh/smtp-router/internal/oidc"
	"github.com/thomasteoh/smtp-router/internal/portal"
	"github.com/thomasteoh/smtp-router/internal/provider"
	"github.com/thomasteoh/smtp-router/internal/ratelimit"
	"github.com/thomasteoh/smtp-router/internal/rules"
	"github.com/thomasteoh/smtp-router/internal/webhook"
)

// Server is the HTTP API server.
type Server struct {
	cfg     *config.Config
	cfgPath string
	auth    *auth.Auth
	audit   *audit.Store
	limit   *ratelimit.Limiter
	rules   *rules.Rules
	hook    *webhook.Dispatcher
	oidc    *oidc.Verifier
	portal  *portal.Portal

	// mu guards the mutable provider map and config slices, which admin
	// endpoints mutate while handleSend reads them.
	mu   sync.RWMutex
	prov map[string]provider.Sender

	// counters for /metrics.
	reqs      atomic.Int64
	delivered atomic.Int64
	rateLimit atomic.Int64
	denied    atomic.Int64
	errors    atomic.Int64
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

// SetConfigPath records the config file path so admin mutations can persist.
func (s *Server) SetConfigPath(p string) { s.cfgPath = p }

// SetPortal attaches the admin web portal to the server's handler.
func (s *Server) SetPortal(p *portal.Portal) { s.portal = p }

// Handler returns the http.Handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /send", s.handleSend)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Admin endpoints (token/OIDC-gated).
	mux.HandleFunc("POST /admin/providers", s.gateAdmin(s.adminAddProvider))
	mux.HandleFunc("GET /admin/providers", s.gateAdmin(s.adminListProviders))
	mux.HandleFunc("DELETE /admin/providers/{name}", s.gateAdmin(s.adminDeleteProvider))
	mux.HandleFunc("POST /admin/accounts", s.gateAdmin(s.adminAddAccount))
	mux.HandleFunc("GET /admin/accounts", s.gateAdmin(s.adminListAccounts))
	mux.HandleFunc("DELETE /admin/accounts/{from}", s.gateAdmin(s.adminDeleteAccount))
	mux.HandleFunc("POST /admin/clients", s.gateAdmin(s.adminAddClient))
	mux.HandleFunc("GET /admin/clients", s.gateAdmin(s.adminListClients))
	mux.HandleFunc("DELETE /admin/clients/{name}", s.gateAdmin(s.adminDeleteClient))
	mux.HandleFunc("POST /admin/rules", s.gateAdmin(s.adminAddRule))
	mux.HandleFunc("GET /admin/rules", s.gateAdmin(s.adminListRules))
	mux.HandleFunc("DELETE /admin/rules", s.gateAdmin(s.adminDeleteRule))
	mux.HandleFunc("GET /admin/audit", s.gateAdmin(s.adminListAudit))
	mux.HandleFunc("GET /admin/usage", s.gateAdmin(s.adminUsage))

	// Admin web portal (OIDC Connect login flow + HTML console). Mounted only
	// when a portal is attached; the portal's own /login, /callback, /logout
	// and /portal routes are exposed regardless of the OIDC verifier state.
	if s.portal != nil {
		s.portal.Register(mux)
	}
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

// sanitizeValue rejects CR/LF in a user-supplied value, preventing MIME header
// injection (e.g. smuggling a Bcc header via Subject).
func sanitizeValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("value contains CR/LF")
	}
	return nil
}

// validateAttach checks an attachment for CR/LF and valid base64.
func validateAttach(a Attach) error {
	if strings.ContainsAny(a.Filename, "\r\n") || strings.ContainsAny(a.ContentType, "\r\n") {
		return fmt.Errorf("attachment filename/content-type contains CR/LF")
	}
	if strings.ContainsAny(a.Filename, "\"") {
		return fmt.Errorf("attachment filename contains a quote")
	}
	if _, err := base64.StdEncoding.DecodeString(a.ContentB64); err != nil {
		return fmt.Errorf("attachment content is not valid base64")
	}
	return nil
}

// handleSend processes a send request.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	s.reqs.Add(1)
	// Caller auth via X-API-Key.
	key := r.Header.Get("X-API-Key")
	client := s.auth.Validate(key)
	if client == "" {
		s.denied.Add(1)
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
	// Reject CR/LF in user-supplied header values (prevents injection).
	for _, v := range []string{req.From, req.Subject} {
		if err := sanitizeValue(v); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, t := range req.To {
		if err := sanitizeValue(t); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, a := range req.Attachments {
		if err := validateAttach(a); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Per-client from-binding: a client may only send from the accounts it is
	// bound to. An empty AllowedFrom means any allowlisted account (default).
	s.mu.RLock()
	clientCfg, hasClient := s.cfg.Clients[client]
	s.mu.RUnlock()
	if hasClient && len(clientCfg.AllowedFrom) > 0 {
		allowed := false
		for _, f := range clientCfg.AllowedFrom {
			if strings.EqualFold(f, req.From) {
				allowed = true
				break
			}
		}
		if !allowed {
			s.record(client, req, audit.StatusDenied, "", req.RequestID)
			http.Error(w, "client not bound to from address", http.StatusForbidden)
			return
		}
	}

	// Sender rules (allow/deny).
	if err := s.rules.Check(req.From); err != nil {
		s.denied.Add(1)
		s.record(client, req, audit.StatusDenied, "", req.RequestID)
		if s.hook != nil {
			s.hook.Fire(r.Context(), webhook.EventDenied, map[string]any{
				"client": client, "from": req.From, "error": err.Error(),
			})
		}
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Resolve account + rate limits (read-only config access under RLock).
	s.mu.RLock()
	acc, ok := s.cfg.LookupAccount(req.From)
	var provName string
	var sender provider.Sender
	if ok {
		provName = req.Provider
		if provName == "" {
			provName = acc.Provider
		}
		if provName != "" {
			sender, ok = s.prov[provName]
		}
	}
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "account not configured", http.StatusForbidden)
		return
	}
	if provName == "" || sender == nil {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}
	dayLimit, monthLimit := acc.Rate.Day, acc.Rate.Month
	if dayLimit == 0 && monthLimit == 0 {
		dayLimit, monthLimit = s.cfg.DefaultRate.Day, s.cfg.DefaultRate.Month
	}

	// Rate limit (day + month).
	if !s.limit.Allow(req.From, dayLimit, monthLimit) {
		s.rateLimit.Add(1)
		s.record(client, req, audit.StatusRateLimited, "", req.RequestID)
		if s.hook != nil {
			s.hook.Fire(r.Context(), webhook.EventRateLimited, map[string]any{
				"client": client, "from": req.From, "provider": provName,
			})
		}
		writeJSON(w, http.StatusTooManyRequests, SendResult{Status: audit.StatusRateLimited})
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
	for _, a := range req.Attachments {
		msg.Attachments = append(msg.Attachments, provider.Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			ContentB64:  a.ContentB64,
		})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := sender.Deliver(ctx, msg); err != nil {
		s.errors.Add(1)
		s.record(client, req, audit.StatusError, err.Error(), req.RequestID)
		if s.hook != nil {
			s.hook.Fire(r.Context(), webhook.EventError, map[string]any{
				"client": client, "from": req.From, "provider": provName, "error": err.Error(),
			})
		}
		writeJSON(w, http.StatusInternalServerError, SendResult{Status: audit.StatusError, Provider: provName, Error: err.Error()})
		return
	}

	s.delivered.Add(1)
	s.record(client, req, audit.StatusDelivered, "", req.RequestID)
	if s.hook != nil {
		s.hook.Fire(r.Context(), webhook.EventDelivered, map[string]any{
			"client": client, "from": req.From, "provider": provName,
		})
	}
	writeJSON(w, http.StatusOK, SendResult{Status: audit.StatusDelivered, Provider: provName})
}

// record writes an audit row for a send.
func (s *Server) record(client string, req SendRequest, status, errMsg, requestID string) {
	if s.audit == nil {
		return
	}
	provName := req.Provider
	s.mu.RLock()
	if acc, ok := s.cfg.LookupAccount(req.From); ok && acc.Provider != "" {
		provName = acc.Provider
	}
	s.mu.RUnlock()
	if err := s.audit.Record(client, req.From, provName, status, errMsg, requestID); err != nil {
		log.Printf("audit: %v", err)
	}
}

// handleHealth returns 200 when the server is up.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// handleReady returns 200 only when the audit store is reachable.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		http.Error(w, "audit store unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.audit.Count(""); err != nil {
		http.Error(w, "audit store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ready")
}

// handleMetrics exposes simple counters as Prometheus-style text.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE smtp_router_requests_total counter\nsmtp_router_requests_total %d\n", s.reqs.Load())
	fmt.Fprintf(w, "# TYPE smtp_router_delivered_total counter\nsmtp_router_delivered_total %d\n", s.delivered.Load())
	fmt.Fprintf(w, "# TYPE smtp_router_rate_limited_total counter\nsmtp_router_rate_limited_total %d\n", s.rateLimit.Load())
	fmt.Fprintf(w, "# TYPE smtp_router_denied_total counter\nsmtp_router_denied_total %d\n", s.denied.Load())
	fmt.Fprintf(w, "# TYPE smtp_router_errors_total counter\nsmtp_router_errors_total %d\n", s.errors.Load())
}

// gateAdmin wraps an admin handler with token or OIDC auth. It fails closed:
// if neither a token nor an OIDC verifier is configured, admin access is
// refused (never open).
func (s *Server) gateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.cfg.AdminToken != "" && tok != "" && subtleEq(tok, s.cfg.AdminToken) {
			next(w, r)
			return
		}
		// Fall back to OIDC if configured.
		if s.oidc != nil && s.cfg.OIDC != nil && tok != "" {
			if _, admin, err := s.oidc.Verify(r.Context(), tok); err == nil && admin {
				next(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// subtleEq compares two tokens in constant time.
func subtleEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// adminAddProvider adds a provider (admin). It accepts a provider JSON body
// and persists the change to the config file.
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
	s.mu.Lock()
	s.cfg.Providers = append(s.cfg.Providers, p)
	s.prov[p.Name] = sender
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": p.Name})
}

// adminAddAccount adds a sending account (admin) and persists the change.
func (s *Server) adminAddAccount(w http.ResponseWriter, r *http.Request) {
	var a config.Account
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&a); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if a.From == "" || a.Provider == "" {
		http.Error(w, "from and provider required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.cfg.Accounts == nil {
		s.cfg.Accounts = make(map[string]config.Account)
	}
	s.cfg.Accounts[a.From] = a
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": a.From})
}

// adminAddClient generates a new per-client API key (admin). The raw key is
// returned once; only its hash is stored and persisted.
func (s *Server) adminAddClient(w http.ResponseWriter, r *http.Request) {
	var c config.Client
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if c.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	raw, err := s.auth.Generate(c.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.cfg.Clients == nil {
		s.cfg.Clients = make(map[string]config.Client)
	}
	s.cfg.Clients[c.Name] = config.Client{Name: c.Name, Key: hashKey(raw), Note: c.Note, AllowedFrom: c.AllowedFrom}
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "client": c.Name, "key": raw})
}

// adminAddRule adds an allowlist or denylist entry (admin) and persists it.
func (s *Server) adminAddRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string   `json:"action"` // "allow" or "deny"
		Rule   string   `json:"rule"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Rule == "" || (req.Action != "allow" && req.Action != "deny") {
		http.Error(w, "action (allow|deny) and rule required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	switch req.Action {
	case "allow":
		s.cfg.Allowlist = append(s.cfg.Allowlist, req.Rule)
	case "deny":
		s.cfg.Denylist = append(s.cfg.Denylist, req.Rule)
	}
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": req.Action, "rule": req.Rule})
}

// adminListProviders lists the configured providers (admin).
func (s *Server) adminListProviders(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := make([]map[string]any, 0, len(s.cfg.Providers))
	for _, p := range s.cfg.Providers {
		out = append(out, map[string]any{
			"name": p.Name, "type": p.Type, "host": p.Host, "port": p.Port,
			"url": p.URL, "method": p.Method, "tls": p.TLS, "starttls": p.StartTLS,
		})
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

// adminDeleteProvider removes a provider by name (admin) and persists.
func (s *Server) adminDeleteProvider(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	for i := range s.cfg.Providers {
		if s.cfg.Providers[i].Name == name {
			s.cfg.Providers = append(s.cfg.Providers[:i], s.cfg.Providers[i+1:]...)
			delete(s.prov, name)
			s.mu.Unlock()
			s.persistConfig()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider": name})
			return
		}
	}
	s.mu.Unlock()
	http.Error(w, "provider not found", http.StatusNotFound)
}

// adminListAccounts lists the configured accounts (admin).
func (s *Server) adminListAccounts(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := make([]map[string]any, 0, len(s.cfg.Accounts))
	for from, a := range s.cfg.Accounts {
		out = append(out, map[string]any{
			"from": from, "provider": a.Provider,
			"rate": map[string]int{"day": a.Rate.Day, "month": a.Rate.Month},
		})
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

// adminDeleteAccount removes an account by from address (admin) and persists.
func (s *Server) adminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	from := r.PathValue("from")
	s.mu.Lock()
	if _, ok := s.cfg.Accounts[from]; !ok {
		s.mu.Unlock()
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	delete(s.cfg.Accounts, from)
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": from})
}

// adminListClients lists clients by name (admin). Keys are never returned.
func (s *Server) adminListClients(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := make([]map[string]any, 0, len(s.cfg.Clients))
	for name, c := range s.cfg.Clients {
		out = append(out, map[string]any{"name": name, "note": c.Note, "allowed_from": c.AllowedFrom})
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

// adminDeleteClient removes a client by name (admin) and persists.
func (s *Server) adminDeleteClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	if _, ok := s.cfg.Clients[name]; !ok {
		s.mu.Unlock()
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}
	delete(s.cfg.Clients, name)
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "client": name})
}

// adminListRules lists the allowlist and denylist (admin).
func (s *Server) adminListRules(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	allow := append([]string(nil), s.cfg.Allowlist...)
	deny := append([]string(nil), s.cfg.Denylist...)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"allow": allow, "deny": deny})
}

// adminDeleteRule removes an allowlist or denylist entry (admin) and persists.
func (s *Server) adminDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "allow" or "deny"
		Rule   string `json:"rule"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Rule == "" || (req.Action != "allow" && req.Action != "deny") {
		http.Error(w, "action (allow|deny) and rule required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	switch req.Action {
	case "allow":
		s.cfg.Allowlist = removeStr(s.cfg.Allowlist, req.Rule)
	case "deny":
		s.cfg.Denylist = removeStr(s.cfg.Denylist, req.Rule)
	}
	s.mu.Unlock()
	s.persistConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": req.Action, "rule": req.Rule})
}

// removeStr removes every occurrence of v from a slice.
func removeStr(in []string, v string) []string {
	out := in[:0]
	for _, s := range in {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

// persistConfig saves the in-memory config to disk when a path is set.
func (s *Server) persistConfig() {
	if s.cfgPath == "" {
		return
	}
	s.mu.RLock()
	err := s.cfg.Save(s.cfgPath)
	s.mu.RUnlock()
	if err != nil {
		log.Printf("persist config: %v", err)
	}
}

// hashKey returns the hex SHA-256 of a raw key, for storage.
func hashKey(raw string) string {
	return auth.HashHex(raw)
}

// adminListAudit lists recent audit rows.
func (s *Server) adminListAudit(w http.ResponseWriter, r *http.Request) {
	n := 0
	_, _ = fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n)
	if n < 0 || n > 1000 {
		n = 100
	}
	rows, err := s.audit.List(n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// adminUsage returns per-account usage counters.
func (s *Server) adminUsage(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	accounts := make(map[string]map[string]int, len(s.cfg.Accounts))
	for name := range s.cfg.Accounts {
		d, m := s.limit.Usage(name)
		accounts[name] = map[string]int{"day": d, "month": m}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, accounts)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

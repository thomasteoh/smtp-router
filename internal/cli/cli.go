// Package cli implements the smtp-router command-line interface: `serve`
// and `admin` subcommands. Admin operations mirror the HTTP admin API.
package cli

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/thomasteoh/smtp-router/internal/auth"
	"github.com/thomasteoh/smtp-router/internal/audit"
	"github.com/thomasteoh/smtp-router/internal/config"
	"github.com/thomasteoh/smtp-router/internal/oidc"
	"github.com/thomasteoh/smtp-router/internal/portal"
	"github.com/thomasteoh/smtp-router/internal/queue"
	"github.com/thomasteoh/smtp-router/internal/ratelimit"
	"github.com/thomasteoh/smtp-router/internal/rules"
	"github.com/thomasteoh/smtp-router/internal/server"
	"github.com/thomasteoh/smtp-router/internal/smtprelay"
	"github.com/thomasteoh/smtp-router/internal/webhook"
)

// Serve runs the HTTP API server and, when a relay address is provided, the
// SMTP-protocol relay listener. Both share the same client keys, rules,
// rate limits, providers, audit store and webhooks.
func Serve(cfgPath, addr, smtpAddr, dbPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg.Normalize()

	// Wire audit.
	ad, err := audit.Open(dbPath)
	if err != nil {
		return err
	}
	defer ad.Close()

	// Wire auth: load clients from config. Config stores hash(raw) (never raw),
	// so Add places the stored hash directly — re-hashing here would double-hash
	// and invalidate every client key after a restart.
	au := auth.New()
	for name, c := range cfg.Clients {
		au.Add(name, c.Key)
	}

	lim := ratelimit.New()
	rl := rules.New(cfg.Allowlist, cfg.Denylist)
	hk := webhook.New(cfg.Webhooks)

	// OIDC verifier (admin access), if configured.
	var ov *oidc.Verifier
	if cfg.OIDC != nil {
		ov = oidc.New(oidc.Config{
			Issuer:      cfg.OIDC.Issuer,
			ClientID:    cfg.OIDC.ClientID,
			Scopes:      cfg.OIDC.Scopes,
			AdminRole:   cfg.OIDC.AdminRole,
			RedirectURL: cfg.OIDC.RedirectURL,
		})
	}

	s, err := server.New(cfg, au, ad, lim, rl, hk, ov)
	if err != nil {
		return err
	}
	// Record the config path so admin mutations persist across restart.
	s.SetConfigPath(cfgPath)

	// Async send queue: build the worker pool and start it when enabled.
	var qctx context.Context
	var qcancel context.CancelFunc
	if cfg.Queue.Enabled {
		qdbPath := cfg.Queue.DBPath
		if qdbPath == "" {
			qdbPath = dbPath + ".queue" // default: alongside the audit db
		}
		qstore, err := queue.Open(qdbPath)
		if err != nil {
			return fmt.Errorf("queue: %w", err)
		}
		// Recover jobs left 'running' by a previous run.
		if _, err := qstore.Recover(5 * time.Second); err != nil {
			return fmt.Errorf("queue recover: %w", err)
		}
		pool := queue.NewPool(qstore, queue.Config{
			Workers:    cfg.Queue.Workers,
			Batch:      cfg.Queue.Batch,
			MaxSize:    cfg.Queue.MaxSize,
			MaxRetries: cfg.Queue.MaxRetries,
			RetryBase:  time.Duration(cfg.Queue.RetryBase) * time.Second,
		}, func(ctx context.Context, job queue.Job) (string, error) {
			// Deliver via the account's provider, honoring per-request
			// override and per-account rate limits at delivery time.
			return s.DeliverJob(ctx, job)
		})
		s.SetQueue(pool)
		qctx, qcancel = context.WithCancel(context.Background())
		go pool.Run(qctx)
		defer func() {
			qcancel()
			_ = qstore.Close()
		}()
	}

	// Admin web portal (OIDC Connect login flow). Reuses the router's verifier
	// for the ID-token admin-role check; the code exchange uses the OIDC
	// client secret from the config.
	if cfg.OIDC != nil {
		s.SetPortal(portal.New(portal.Config{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			Scopes:       cfg.OIDC.Scopes,
			AdminRole:    cfg.OIDC.AdminRole,
			RedirectURL:  cfg.OIDC.RedirectURL,
		}, ov))
	}

	// SMTP-protocol relay listener. When smtpAddr is set, downstream apps
	// (Zulip, Zitadel, Vaultwarden, Wiki.js) can relay through the router by
	// authenticating with their client key (username=client, password=key).
	// The relay reuses the same pipeline as /send.
	var relay *smtprelay.Server
	if smtpAddr != "" {
		relay = smtprelay.New(smtprelay.Config{
			Addr:    smtpAddr,
			Auth:    s, // server implements smtprelay.Authenticator
			Deliver: s, // server implements smtprelay.Deliverer
		})
		if err := relay.Listen(); err != nil {
			return err
		}
		fmt.Printf("smtp-router smtp relay listening on %s\n", smtpAddr)
		rctx, rcancel := context.WithCancel(context.Background())
		go func() { _ = relay.Serve(rctx) }()
		defer func() {
			rcancel()
			_ = relay.Close()
		}()
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	fmt.Printf("smtp-router listening on %s (db %s)\n", addr, dbPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Admin runs an admin subcommand.
func Admin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: smtp-router admin <subcommand> [args]")
	}
	sub := args[0]
	switch sub {
	case "add-client":
		return adminAddClient(args[1:])
	case "list-clients":
		return adminListClients(args[1:])
	case "usage":
		return adminUsage(args[1:])
	case "list-audit":
		return adminListAudit(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", sub)
	}
}

func adminAddClient(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: smtp-router admin add-client <name>")
	}
	name := args[0]
	au := auth.New()
	key, err := au.Generate(name)
	if err != nil {
		return err
	}
	fmt.Printf("client=%s key=%s\n", name, key)
	return nil
}

func adminListClients(args []string) error {
	// In this minimal CLI we read clients from config and print names.
	cfgPath := firstNonEmpty(args, "")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	for name := range cfg.Clients {
		fmt.Println(name)
	}
	return nil
}

func adminUsage(args []string) error {
	// Read the audit store and print per-account counts for the current
	// windows (day + month) from the limiter state. In this minimal CLI we
	// report audit counts by status.
	dbPath := firstNonEmpty(args, "smtp-router.db")
	ad, err := audit.Open(dbPath)
	if err != nil {
		return err
	}
	defer ad.Close()
	rows, err := ad.List(0)
	if err != nil {
		return err
	}
	byStatus := map[string]int{}
	byFrom := map[string]int{}
	for _, r := range rows {
		byStatus[r.Status]++
		byFrom[r.From]++
	}
	fmt.Println("by status:")
	for k, v := range byStatus {
		fmt.Printf("  %-12s %d\n", k, v)
	}
	fmt.Println("by account:")
	for k, v := range byFrom {
		fmt.Printf("  %-24s %d\n", k, v)
	}
	return nil
}

func adminListAudit(args []string) error {
	dbPath := firstNonEmpty(args, "smtp-router.db")
	ad, err := audit.Open(dbPath)
	if err != nil {
		return err
	}
	defer ad.Close()
	rows, err := ad.List(50)
	if err != nil {
		return err
	}
	for _, r := range rows {
		fmt.Printf("%s %-10s %-20s %-12s %s\n", r.TS, r.Client, r.From, r.Status, r.Provider)
	}
	return nil
}

// Health checks that the audit store is reachable. It is designed to be
// exec-able by a container healthcheck without any shell or network tools.
func Health(dbPath string) error {
	if dbPath == "" {
		dbPath = "smtp-router.db"
	}
	ad, err := audit.Open(dbPath)
	if err != nil {
		return err
	}
	defer ad.Close()
	if _, err := ad.Count(""); err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func firstNonEmpty(args []string, def string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return def
}

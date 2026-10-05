// Command smtp-router is a lightweight outbound email routing service.
//
// It accepts send requests from first-party apps over an internal HTTP JSON
// API, applies sender allow/deny rules, selects an upstream delivery provider
// (SMTP or provider HTTP API), enforces per-account day+month rate limits,
// records a durable audit log, and fires webhooks on send outcome. It is a
// routing/relay layer only — no mailbox, IMAP, or inbound (MX) mail.
//
// Admin operations (providers, accounts, rules, clients/keys, audit, OIDC)
// are exposed both as CLI subcommands and as a token-gated HTTP API. Human
// admin access integrates Zitadel via OIDC, role-gated.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thomasteoh/smtp-router/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: smtp-router <serve|admin|health> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		cfgPath := fs.String("config", "", "path to config file (env or YAML)")
		addr := fs.String("addr", ":8080", "listen address")
		dbPath := fs.String("db", "smtp-router.db", "sqlite audit database path")
		if err := fs.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := cli.Serve(*cfgPath, *addr, *dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case "admin":
		if err := cli.Admin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
	case "health":
		fs := flag.NewFlagSet("health", flag.ContinueOnError)
		dbPath := fs.String("db", "smtp-router.db", "sqlite audit database path")
		if err := fs.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := cli.Health(*dbPath); err != nil {
			fmt.Fprintln(os.Stderr, "health:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(2)
	}
}

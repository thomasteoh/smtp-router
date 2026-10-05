# harmonicr smtp-router

A lightweight outbound email routing service for the harmonicr infrastructure.
It accepts send requests from first-party apps, applies sender allow/deny rules,
selects an upstream delivery provider (SMTP or provider HTTP API), enforces
per-account day+month rate limits, records a durable audit log, and fires
webhooks on send outcome.

It is a routing/relay layer only — it does not run a mailbox, IMAP, or a full
MTA, and it does not receive mail.

## Why

Central outbound email policy for all harmonicr/awry services:

- **Per-account quota** (day + month windows) so no service can send unlimited
  mail as any account.
- **Provider abstraction** — add/switch an SMTP or API provider in one place.
- **Sender rules** (allowlist/denylist) and a central audit trail.
- **Webhooks** on send outcome for downstream automation.
- **CLI + API management**; human admin access via OIDC (Zitadel).

## Build

```sh
go build ./...
go test ./...
```

## Run (serve)

```sh
smtp-router serve -config config.json -addr :8080 -db smtp-router.db
```

Environment variables may be used in place of a file: set `EMAIL_ROUTER_CONFIG`
to a config path, `EMAIL_ROUTER_ADMIN_TOKEN` for the admin token, and
`EMAIL_ROUTER_DEFAULT_DAY` / `EMAIL_ROUTER_DEFAULT_MONTH` for the default rate.

## Send

```sh
curl -X POST http://127.0.0.1:8080/send \
  -H 'X-API-Key: <client-key>' \
  -d '{"from":"alerts@harmonicr.com","to":["x@example.com"],
       "subject":"hi","body":"hello"}'
```

Response statuses: `200 delivered`, `429 rate_limited`, `403 denied`,
`401 unauthorized`, `500 error`.

## Admin

```sh
# CLI
smtp-router admin add-client <name>       # prints a new per-client key
smtp-router admin list-clients
smtp-router admin usage
smtp-router admin list-audit

# API (token-gated)
curl -H 'Authorization: Bearer <admin-token>' http://127.0.0.1:8080/admin/audit
```

Human admin access is available via OIDC (Zitadel, `auth.harmonicr.com`),
role-gated. See `config.json.example`.

## Config

See `config.json.example` for the full shape: providers (smtp|api), accounts
(with per-account day+month rate limits), allowlist/denylist, clients
(per-client API keys), webhooks, and OIDC settings.

## Deploy

Built as a container image via GitHub Actions → **GHCR**
(`ghcr.io/thomasteoh/smtp-router`), pulled on the solo VM and run rootless
under Podman. See `.github/workflows/build-and-publish.yml`.

## Security

- Per-client API keys (generated, stored hashed) gate `POST /send`.
- No open relay: only allowlisted `from` addresses may send; denylist enforced.
- Upstream credentials live in the container env/secret file, never returned to
  callers, never logged.
- Logs record client + account + provider + status only — never message content.
- Admin API is token-gated; human access via OIDC with role gating.
- Webhooks are HMAC-signed so receivers can verify authenticity.

## Scope boundaries

Deliberately **not** included: mailbox/IMAP, inbound (MX) mail, spam filtering,
DKIM signing at this layer, and a web UI (CLI + API only).

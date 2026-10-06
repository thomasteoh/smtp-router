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

Install to PATH:

```sh
go install github.com/thomasteoh/smtp-router/cmd/smtp-router@latest
```

## Run (serve)

```sh
smtp-router serve -config config.json -addr :8080 -db smtp-router.db
```

Environment variables may be used in place of a file: set `SMTP_ROUTER_CONFIG`
to a config path, `SMTP_ROUTER_ADMIN_TOKEN` for the admin token, and
`SMTP_ROUTER_DEFAULT_DAY` / `SMTP_ROUTER_DEFAULT_MONTH` for the default rate.
The server refuses to start without an admin token (admin access fails closed)
and without at least one provider and one account.

## Send

```sh
curl -X POST http://127.0.0.1:8080/send \
  -H 'X-API-Key: <client-key>' \
  -d '{"from":"alerts@harmonicr.com","to":["x@example.com"],
       "subject":"hi","body":"hello"}'
```

Attachments (optional, base64 content):

```sh
curl -X POST http://127.0.0.1:8080/send \
  -H 'X-API-Key: <client-key>' \
  -d '{"from":"alerts@harmonicr.com","to":["x@example.com"],
       "subject":"hi","body":"hello",
       "attachments":[{"filename":"report.pdf",
                       "content_type":"application/pdf",
                       "content_b64":"JVBERi0xLjQK..."}]}'
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

### Admin web portal

The router also serves an OIDC Connect admin web console (no separate
service) at the site root. Visit `https://smtp.harmonicr.com/`:

- `GET /` renders the embedded HTML console (redirects to `/login` when no
  session), which calls the token-gated admin API using the session's ID token
  as a Bearer credential.
- `GET /login` redirects to Zitadel authorize (OIDC authorization-code flow).
- `GET /callback` exchanges the code, verifies the ID token via the router's
  OIDC verifier, checks the `admin` role, and sets a session cookie
  (`smtp_router_sess`, HttpOnly/Secure, 12h).
- `GET /logout` clears the session.

The web UI lives at the repo root in `web/` (`web/web.go` embeds
`web/index.html`; the portal package imports `web` and serves it). The console
manages providers, accounts, clients (API keys), allow/deny rules, and shows
audit + usage. The OIDC app must have role assertions enabled (the
`admin` role key must ride the ID token) and the user must hold the `admin`
role on the internal project.

## Config

See `config.json.example` for the full shape: providers (smtp|api), accounts
(with per-account day+month rate limits), allowlist/denylist, clients
(per-client API keys), webhooks, and OIDC settings.

## Deploy

Built as a container image via GitHub Actions → **GHCR**
(`ghcr.io/thomasteoh/smtp-router`), pulled on the solo VM and run rootless
under Podman. See `.github/workflows/build-and-publish.yml`.

Local container run:

```sh
podman run --rm -p 52150:8080 \
  -v /opt/smtp-router:/opt/smtp-router:ro \
  -v smtp-router-data:/opt/smtp-router-data \
  -e SMTP_ROUTER_ADMIN_TOKEN=... \
  ghcr.io/thomasteoh/smtp-router:latest \
  serve -config /opt/smtp-router/config.json -db /opt/smtp-router-data/smtp-router.db
```

## Security

- Per-client API keys (generated, stored hashed) gate `POST /send`. A client
  may only send from the `from` addresses it is bound to (`allowed_from`).
- No open relay: only allowlisted `from` addresses may send; denylist enforced.
- Header injection is blocked: CR/LF in `from`, `to`, `subject`, or attachment
  filenames/content types is rejected before any MIME is built.
- SMTP providers support STARTTLS and implicit TLS (no cleartext delivery when
  configured); API providers require the upstream be configured with a URL.
- Upstream credentials live in the container env/secret file, never returned to
  callers, never logged.
- Logs record client + account + provider + status only — never message content.
- Admin API is token-gated and fails closed (no token configured = no admin
  access); human access via OIDC with role gating.
- Webhooks are HMAC-signed so receivers can verify authenticity.
- Server timeouts (read/header/write/idle) are set on the HTTP listener.

## Scope boundaries

Deliberately **not** included: mailbox/IMAP, inbound (MX) mail, spam filtering,
DKIM signing at this layer, and a web UI (CLI + API only).

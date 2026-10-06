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

## Async send queue

When `queue.enabled` is true, `POST /send` becomes asynchronous: instead of
delivering synchronously, the router enqueues the send and returns
`202 accepted` with a `job_id`. A worker pool drains the queue, applying
per-account rate limits at delivery time so a burst is paced rather than
rejected outright. When disabled (default), sends stay synchronous.

Useful features:

- **Scheduling** — `send_at` (RFC3339) defers a send; jobs are not claimed
  before their due time.
- **Prioritisation** — `priority` (higher = more urgent) drains first; FIFO
  within the same priority.
- **Retry with backoff** — transient delivery failures are retried up to
  `max_retries`; after that the job moves to `dead`. A rate-limited delivery
  re-queues without counting an attempt.
- **Crash recovery** — jobs left `running` by a killed process are re-queued
  on startup.
- **Admin API** (token-gated) — `GET /admin/queue` (depth + counters),
  `GET /admin/queue/jobs` (list, optional `?status=`), and
  `DELETE /admin/queue/jobs/{id}` (cancel a queued job).

The queue DB defaults to `<audit-db>.queue` alongside the audit database.
See `config.json.example` for the `queue` block. Note: an account still maps
to a single provider — cross-provider allocation (round-robin / tier-based /
proportional) is not implemented.

## Config

See `config.json.example` for the full shape: providers (smtp|api), accounts
(with per-account day+month rate limits), allowlist/denylist, clients
(per-client API keys), webhooks, and OIDC settings.

## Deploy

Built as a container image via GitHub Actions → **GHCR**
(`ghcr.io/thomasteoh/smtp-router`), pulled on the solo VM and run rootless
under Podman. See `.github/workflows/build-and-publish.yml`.

The production deployment uses the repo's `compose.yaml` (rootless Podman
compose, host networking, `userns_mode: keep-id:uid=10001,gid=10001`) managed
by a `deploy`-user systemd unit:

- Config bind-mounted **rw** at `/opt/smtp-router` so admin mutations
  (add-provider/account/client, add-rule) persist back to `config.json`.
- Data volume `smtp-router-data` at `/opt/smtp-router-data` holds the SQLite DB
  (audit + usage + providers/accounts/clients), so it survives container
  recreation.
- Caddy terminates TLS at `smtp.harmonicr.com` and reverse-proxies to
  `127.0.0.1:52150`; the router binds `:52150` under host networking.
- The systemd user unit (`podman-compose-smtp-router.service`) runs
  `podman-compose up -d --no-build` on boot and is enabled (symlinked into
  `default.target.wants`); `deploy` has linger enabled so the unit runs without
  a login.

Manual operations on the VM (as `deploy`):

```sh
podman-compose -f /opt/smtp-router/compose.yaml up -d --no-build   # start
podman-compose -f /opt/smtp-router/compose.yaml down               # stop
# After pulling a new image, force-recreate so the new image is used:
podman-compose -f /opt/smtp-router/compose.yaml up -d --force-recreate
```

> **Note**: `podman restart smtp-router` does **not** pick up a freshly pulled
> `:latest` (it reuses the image the container was created from). Always use
> `podman-compose up -d --force-recreate` after a pull.

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
and DKIM signing at this layer. Management is CLI + API + an OIDC web console
(see Admin web portal above); the console is served by the router itself, not a
separate UI service.

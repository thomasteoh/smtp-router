# Security Policy

## Supported versions

The latest release on `main` is supported. Security fixes land on `main`
first and are released from there.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security problem. Email
the maintainer directly:

- **Thomas Teoh** — `thomas@awry.com.au`

Include:

- A description of the vulnerability and its impact.
- The steps to reproduce, or a minimal proof-of-concept.
- The affected versions.
- Any suggested fix, if you have one.

Please give us a reasonable time to respond before public disclosure. We
acknowledge reports and aim to fix them promptly.

## What this project guards against

- **Header injection** — CR/LF in user-supplied values is rejected before any
  MIME is built, so no header smuggling.
- **Admin fail-open** — the admin API refuses requests when no token/OIDC is
  configured (fails closed).
- **Open relay** — only allowlisted `from` addresses may send; denylist
  enforced; clients are bound to their `from` addresses.
- **Credential handling** — upstream credentials live in the container
  env/secret file, never returned to callers, never logged.
- **Message privacy** — the audit log records metadata only, never content.
- **Data race** — the provider map is mutex-guarded; `go test -race` runs in CI.

## Security model

- `POST /send` is gated by per-client API keys (generated, stored hashed).
- Admin endpoints are token-gated (fails closed) or OIDC role-gated.
- Webhooks are HMAC-signed so receivers can verify authenticity.
- The HTTP listener sets read/header/write/idle timeouts.

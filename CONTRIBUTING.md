# Contributing

Thanks for contributing to smtp-router. This is a small, focused Go project;
please keep changes consistent with the existing style and scope.

## Setup

```sh
go build ./...
go test ./...
```

Use the Go version pinned in `go.mod`. Run `go vet ./...` before opening a PR.

## What to change

- **Bug fixes and security hardening** are welcome and reviewed first.
- **Features** must fit the scope: it is an outbound email *router* — no
  mailbox, IMAP, or inbound (MX) mail, no spam filtering, no DKIM signing at
  this layer, and no web UI (CLI + API only).
- Keep the audit log metadata-only: never log or store message content.

## Tests

Every fix should come with a regression test where practical. The test suite
must stay green under `go test -race ./...` — the race detector is part of CI.

## Pull requests

- Open a PR against `main`.
- Describe the change and why (not just what).
- Reference any security issue in the description if it's a fix.

## Reporting security issues

See `SECURITY.md`. Do not open a public issue for a security bug; email the
maintainer per that file.

## Code of conduct

Be respectful and constructive. This is a small project with a small set of
maintainers — assume good faith and keep reviews civil.

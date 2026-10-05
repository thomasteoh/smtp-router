# harmonicr smtp-router — multi-stage Go build, minimal scratch runtime.
# Build the static binary, then copy it into a distroless-style container.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /smtp-router ./cmd/smtp-router

FROM scratch
# CA certificates are REQUIRED: the router verifies OIDC ID tokens against
# https://auth.harmonicr.com (Let's Encrypt cert) and may call API providers
# over HTTPS; without a CA bundle Go's x509 verifier rejects those certs.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /smtp-router /smtp-router
# Run as non-root (uid 10001 to match the harmonicr rootless pattern).
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/smtp-router"]

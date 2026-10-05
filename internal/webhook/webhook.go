// Package webhook posts send outcomes to configured endpoints with an HMAC
// signature so receivers can verify authenticity.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/thomasteoh/smtp-router/internal/config"
)

// Event names.
const (
	EventDelivered   = "delivered"
	EventRateLimited = "rate_limited"
	EventError       = "error"
	EventDenied      = "denied"
)

// Dispatcher posts webhooks to configured endpoints.
type Dispatcher struct {
	Webhooks []config.Webhook
	client   *http.Client
}

// New builds a Dispatcher.
func New(ws []config.Webhook) *Dispatcher {
	return &Dispatcher{Webhooks: ws, client: &http.Client{Timeout: 10 * time.Second}}
}

// Fire sends a webhook for the given event. It is best-effort: a failed
// endpoint is logged but does not fail the send.
func (d *Dispatcher) Fire(ctx context.Context, event string, payload map[string]any) {
	for _, w := range d.Webhooks {
		if !wants(w.Events, event) {
			continue
		}
		b, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Smtp-Router-Event", event)
		if w.Secret != "" {
			mac := hmac.New(sha256.New, []byte(w.Secret))
			mac.Write(b)
			req.Header.Set("X-Smtp-Router-Signature", hex.EncodeToString(mac.Sum(nil)))
		}
		resp, err := d.client.Do(req)
		if err != nil {
			// best-effort; continue to other endpoints
			continue
		}
		_ = resp.Body.Close()
	}
}

func wants(events []string, event string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

// VerifySignature checks an incoming HMAC signature against a secret.
func VerifySignature(secret, body []byte, sig string) bool {
	if len(secret) == 0 || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig))
}

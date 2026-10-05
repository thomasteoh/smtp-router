// Package provider delivers a rendered MIME message to an upstream delivery
// provider. Two provider types are supported: SMTP (smtp/smtps, with auth)
// and a provider HTTP API (e.g. a REST endpoint that accepts the message).
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/harmonicr/email-router/internal/config"
)

// Sender is the interface a delivery provider implements.
type Sender interface {
	// Deliver sends a message. It returns a non-nil error on failure; the
	// caller decides the send status (delivered vs error).
	Deliver(ctx context.Context, msg Message) error
}

// Message is the fully-rendered message to deliver.
type Message struct {
	From    string
	To      []string
	Subject string
	Body    string
	HTML    string
	Headers []Header
}

// Header is an extra MIME header (e.g. Reply-To).
type Header struct {
	Name  string
	Value string
}

// New builds a Sender for a provider config. It returns an error for an
// unsupported provider type.
func New(p config.Provider) (Sender, error) {
	switch p.Type {
	case "smtp":
		return &smtpSender{p: p}, nil
	case "api":
		return &apiSender{p: p}, nil
	default:
		return nil, fmt.Errorf("unsupported provider type %q", p.Type)
	}
}

// smtpSender delivers over SMTP using net/smtp.
type smtpSender struct {
	p config.Provider
}

func (s *smtpSender) Deliver(ctx context.Context, msg Message) error {
	host := s.p.Host
	port := s.p.Port
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	// Build the MIME message.
	var buf bytes.Buffer
	h := textproto.MIMEHeader{}
	h.Set("From", msg.From)
	h.Set("To", strings.Join(msg.To, ","))
	h.Set("Subject", msg.Subject)
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	for _, extra := range msg.Headers {
		h.Set(extra.Name, extra.Value)
	}

	// Content-Type: multipart/alternative when HTML present, else text/plain.
	ct := "text/plain; charset=utf-8"
	if msg.HTML != "" {
		ct = `multipart/alternative; boundary="harmonicr"` + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	h.Set("Content-Type", ct)
	h.Set("MIME-Version", "1.0")

	// Write headers.
	for k, v := range h {
		for _, vv := range v {
			buf.WriteString(k + ": " + vv + "\r\n")
		}
	}
	buf.WriteString("\r\n")

	if msg.HTML == "" {
		buf.WriteString(msg.Body)
	} else {
		// multipart/alternative: text + html parts
		buf.WriteString("--" + boundary(h) + "\r\n")
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		buf.WriteString(msg.Body + "\r\n")
		buf.WriteString("--" + boundary(h) + "\r\n")
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
		buf.WriteString(msg.HTML + "\r\n")
		buf.WriteString("--" + boundary(h) + "--\r\n")
	}

	// SMTP auth.
	var auth smtp.Auth
	if s.p.Auth != "" {
		user, pass, _ := strings.Cut(s.p.Auth, ":")
		auth = smtp.PlainAuth("", user, pass, host)
	}

	// Use a context-aware dial: net/smtp has no context support, so wrap the
	// deadline via a client with a timeout and rely on the caller's ctx.
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer c.Close()
	if err := c.Hello(host); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(msg.From); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	for _, to := range msg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp rcpt: %w", err)
		}
	}
	dw, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := dw.Write(buf.Bytes()); err != nil {
		dw.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := dw.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return nil
}

// apiSender delivers over a provider HTTP API.
type apiSender struct {
	p config.Provider
}

func (s *apiSender) Deliver(ctx context.Context, msg Message) error {
	if s.p.URL == "" {
		return fmt.Errorf("api provider %q has no url", s.p.Name)
	}
	payload := map[string]any{
		"from":    msg.From,
		"to":      msg.To,
		"subject": msg.Subject,
		"body":    msg.Body,
		"html":    msg.HTML,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.p.URL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.p.Token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("api send: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("api provider status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// boundary returns the multipart boundary from the Content-Type header value.
// The smtpSender uses a timestamp-derived boundary; parse it back out.
func boundary(h textproto.MIMEHeader) string {
	ct := h.Get("Content-Type")
	if i := strings.Index(ct, `boundary="`); i >= 0 {
		rest := ct[i+len(`boundary="`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j]
		}
	}
	return ""
}

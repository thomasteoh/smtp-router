// Package provider delivers a rendered MIME message to an upstream delivery
// provider. Two provider types are supported: SMTP (smtp/smtps/starttls, with
// auth) and a provider HTTP API (e.g. a REST endpoint that accepts the
// message).
package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/thomasteoh/smtp-router/internal/config"
)

// Sender is the interface a delivery provider implements.
type Sender interface {
	// Deliver sends a message. It returns a non-nil error on failure; the
	// caller decides the send status (delivered vs error).
	Deliver(ctx context.Context, msg Message) error
}

// Message is the fully-rendered message to deliver.
type Message struct {
	From        string
	To          []string
	Subject     string
	Body        string
	HTML        string
	Headers     []Header
	Attachments []Attachment
}

// Header is an extra MIME header (e.g. Reply-To).
type Header struct {
	Name  string
	Value string
}

// Attachment is a MIME attachment. ContentB64 is the base64-encoded file
// content; it is validated before use.
type Attachment struct {
	Filename    string
	ContentType string
	ContentB64  string
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

// sanitizeHeader rejects a header value containing CR/LF, preventing MIME
// header injection (e.g. smuggling a Bcc or Reply-To header via Subject).
func sanitizeHeader(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("header value contains CR/LF")
	}
	return nil
}

// randomBoundary returns a cryptographically-random multipart boundary.
func randomBoundary() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// validateAttachment checks an attachment's filename and content type for
// CR/LF and verifies the content is valid base64.
func validateAttachment(a Attachment) error {
	if strings.ContainsAny(a.Filename, "\r\n") || strings.ContainsAny(a.ContentType, "\r\n") {
		return fmt.Errorf("attachment filename/content-type contains CR/LF")
	}
	if strings.ContainsAny(a.Filename, "\"") {
		return fmt.Errorf("attachment filename contains a quote")
	}
	if _, err := base64.StdEncoding.DecodeString(a.ContentB64); err != nil {
		return fmt.Errorf("attachment content is not valid base64")
	}
	return nil
}

// smtpSender delivers over SMTP using net/smtp, with optional TLS or STARTTLS.
type smtpSender struct {
	p config.Provider
}

func (s *smtpSender) Deliver(ctx context.Context, msg Message) error {
	host := s.p.Host
	port := s.p.Port
	if port == 0 {
		if s.p.TLS || s.p.StartTLS {
			port = 465
		} else {
			port = 587
		}
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	// Reject CR/LF in any header value (defense-in-depth; the server also
	// validates, but providers are also usable directly).
	for _, v := range []string{msg.From, msg.Subject} {
		if err := sanitizeHeader(v); err != nil {
			return err
		}
	}
	for _, t := range msg.To {
		if err := sanitizeHeader(t); err != nil {
			return err
		}
	}
	for _, h := range msg.Headers {
		if err := sanitizeHeader(h.Name); err != nil {
			return err
		}
		if err := sanitizeHeader(h.Value); err != nil {
			return err
		}
	}
	for _, a := range msg.Attachments {
		if err := validateAttachment(a); err != nil {
			return err
		}
	}

	// Build the MIME message body.
	var body bytes.Buffer
	contentType, err := buildMIME(&body, msg)
	if err != nil {
		return err
	}

	h := textproto.MIMEHeader{}
	h.Set("From", msg.From)
	h.Set("To", strings.Join(msg.To, ","))
	h.Set("Subject", msg.Subject)
	h.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
	for _, extra := range msg.Headers {
		h.Set(extra.Name, extra.Value)
	}
	h.Set("Content-Type", contentType)
	h.Set("MIME-Version", "1.0")

	var buf bytes.Buffer
	for k, v := range h {
		for _, vv := range v {
			buf.WriteString(k + ": " + vv + "\r\n")
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body.Bytes())

	// SMTP auth.
	var auth smtp.Auth
	if s.p.Auth != "" {
		user, pass, _ := strings.Cut(s.p.Auth, ":")
		auth = smtp.PlainAuth("", user, pass, host)
	}

	// Dial (context-aware). Implicit TLS uses a tls.Dialer; plain/STARTTLS
	// dials TCP and upgrades after EHLO.
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	if s.p.TLS {
		td := &tls.Dialer{NetDialer: dialer}
		var err error
		conn, err = td.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
	} else {
		var err error
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()
	if err := c.Hello(host); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if s.p.StartTLS {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
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
		_ = dw.Close()
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

// buildMIME writes the message body to buf and returns the Content-Type. It
// builds a multipart/mixed (with nested alternative) when attachments exist,
// multipart/alternative when HTML is present, else a plain text body.
func buildMIME(buf *bytes.Buffer, msg Message) (string, error) {
	switch {
	case len(msg.Attachments) > 0:
		b := randomBoundary()
		ct := `multipart/mixed; boundary="` + b + `"`
		buf.WriteString("--" + b + "\r\n")
		if msg.HTML != "" {
			ab := randomBoundary()
			buf.WriteString("Content-Type: multipart/alternative; boundary=\"" + ab + "\"\r\n\r\n")
			buf.WriteString("--" + ab + "\r\n")
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
			buf.WriteString(msg.Body + "\r\n")
			buf.WriteString("--" + ab + "\r\n")
			buf.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
			buf.WriteString(msg.HTML + "\r\n")
			buf.WriteString("--" + ab + "--\r\n")
		} else {
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
			buf.WriteString(msg.Body + "\r\n")
		}
		for _, a := range msg.Attachments {
			buf.WriteString("--" + b + "\r\n")
			buf.WriteString("Content-Type: " + a.ContentType + "\r\n")
			buf.WriteString("Content-Disposition: attachment; filename=\"" + a.Filename + "\"\r\n")
			buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
			buf.WriteString(a.ContentB64 + "\r\n")
		}
		buf.WriteString("--" + b + "--\r\n")
		return ct, nil
	case msg.HTML != "":
		b := randomBoundary()
		ct := `multipart/alternative; boundary="` + b + `"`
		buf.WriteString("--" + b + "\r\n")
		buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		buf.WriteString(msg.Body + "\r\n")
		buf.WriteString("--" + b + "\r\n")
		buf.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
		buf.WriteString(msg.HTML + "\r\n")
		buf.WriteString("--" + b + "--\r\n")
		return ct, nil
	default:
		buf.WriteString(msg.Body)
		return "text/plain; charset=utf-8", nil
	}
}

// apiSender delivers over a provider HTTP API.
type apiSender struct {
	p config.Provider
}

func (s *apiSender) Deliver(ctx context.Context, msg Message) error {
	if s.p.URL == "" {
		return fmt.Errorf("api provider %q has no url", s.p.Name)
	}
	method := s.p.Method
	if method == "" {
		method = http.MethodPost
	}
	payload := map[string]any{
		"from":    msg.From,
		"to":      msg.To,
		"subject": msg.Subject,
		"body":    msg.Body,
		"html":    msg.HTML,
	}
	if len(msg.Attachments) > 0 {
		atts := make([]map[string]any, 0, len(msg.Attachments))
		for _, a := range msg.Attachments {
			atts = append(atts, map[string]any{
				"filename":     a.Filename,
				"content_type": a.ContentType,
				"content_b64":  a.ContentB64,
			})
		}
		payload["attachments"] = atts
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, method, s.p.URL, bytes.NewReader(b))
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
	// Cap the response body read to avoid unbounded memory use.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("api provider status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

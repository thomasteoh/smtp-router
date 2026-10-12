// Package smtprelay implements the SMTP-protocol listener for smtp-router.
//
// It speaks the server side of SMTP/ESMTP so that off-the-shelf apps (Zulip,
// Zitadel, Vaultwarden, Wiki.js) can relay through the router without knowing
// its HTTP JSON API. Clients authenticate with SMTP AUTH using the same
// per-client credentials the HTTP /send path uses: username = client name,
// password = the client's API key. Every message is then pushed through the
// same rules / rate-limit / provider / audit / webhook pipeline as /send, so
// there is no separate trust model.
//
// Security: the listener requires AUTH before MAIL FROM (fail-closed). It
// never relays unauthenticated mail — no open relay. It only accepts mail
// from addresses the authenticated client is bound to (or any allowlisted
// account when the client has no explicit binding), and only to recipients
// that pass the sender allow/deny rules.
package smtprelay

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// Authenticator maps SMTP credentials to a client name. The SMTP relay uses
// the same client keys as the HTTP /send path: username = client, password =
// the client's raw API key. An empty return means auth failed.
type Authenticator interface {
	// Validate reports whether the presented username/password pair is a
	// known client. It returns the client name on success, "" on failure.
	Validate(user, pass string) string
}

// Deliverer is the server-side send pipeline. It is called after a message
// is fully received (DATA). It performs rules/rate-limit/provider delivery
// and returns an SMTP-style code and message. Status strings are used only
// for logging; the code is what the client sees.
type Deliverer interface {
	// Deliver sends a message on behalf of a client. It returns an SMTP
	// status code (e.g. 250, 450, 550) and a human-readable message.
	Deliver(ctx context.Context, client string, req RelayMessage) (int, string)
}

// RelayMessage is a fully-parsed SMTP message handed to the deliverer.
type RelayMessage struct {
	From    string
	To      []string
	Subject string
	Body    string
	Headers map[string]string
}

// Server is the SMTP-protocol listener.
type Server struct {
	addr     string
	auth     Authenticator
	deliver  Deliverer
	timeout  time.Duration
	maxBytes int64

	ln  net.Listener
	ctx context.Context
}

// Config holds the listener configuration.
type Config struct {
	Addr     string // listen address, e.g. "0.0.0.0:52151"
	Auth     Authenticator
	Deliver  Deliverer
	Timeout  time.Duration // idle/read timeouts (default 5m)
	MaxBytes int64         // max DATA size in bytes (default 25 MiB)
}

// New builds an SMTP relay server.
func New(cfg Config) *Server {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 25 << 20 // 25 MiB
	}
	return &Server{
		addr:     cfg.Addr,
		auth:     cfg.Auth,
		deliver:  cfg.Deliver,
		timeout:  cfg.Timeout,
		maxBytes: cfg.MaxBytes,
	}
}

// Listen opens the listener. It returns an error if the address is invalid
// or already in use.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp relay listen: %w", err)
	}
	s.ln = ln
	return nil
}

// Addr returns the listener address after Listen ("" before).
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return fmt.Errorf("smtp relay: Listen not called")
	}
	s.ctx = ctx
	go func() {
		<-ctx.Done()
		if s.ln != nil {
			_ = s.ln.Close()
		}
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			// Listener closed (shutdown or context cancel).
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		go s.handleConn(c)
	}
}

// Close closes the listener.
func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

// handleConn processes a single SMTP connection.
func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(s.timeout))

	var (
		authUser string // authenticated client name ("" = not authed)
		from     string
		to       []string
		body     strings.Builder
	)

	r := bufio.NewReaderSize(c, 64*1024)
	w := bufio.NewWriter(c)

	// 220 greeting.
	if err := writeLine(w, "220 smtp.harmonicr.com ESMTP\r\n"); err != nil {
		return
	}

	for {
		line, err := readLine(r, 8192)
		if err != nil {
			return
		}
		// Empty line is an SMTP protocol error after greeting; ignore.
		if line == "" {
			continue
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		arg := ""
		if i := strings.IndexAny(line, " 	"); i >= 0 {
			arg = strings.TrimSpace(line[i+1:])
		}

		switch {
		case cmd == "EHLO" || strings.HasPrefix(cmd, "EHLO ") || cmd == "HELO" || strings.HasPrefix(cmd, "HELO "):
			if authUser != "" {
				// Already authed; re-EHLO resets the transaction.
				from, to, body = "", nil, strings.Builder{}
			}
			if err := writeEHLO(w, authUser != ""); err != nil {
				return
			}

		case cmd == "AUTH" || strings.HasPrefix(cmd, "AUTH "):
			if authUser != "" {
				// Already authenticated.
				if err := writeLine(w, "503 Already authenticated\r\n"); err != nil {
					return
				}
				continue
			}
			user, pass, ok := parseAuth(arg)
			if !ok {
				if err := writeLine(w, "504 Unrecognized authentication type\r\n"); err != nil {
					return
				}
				continue
			}
			// AUTH LOGIN is two-step: challenge for username, then password.
			// parseAuth returns ("","",true) for LOGIN; PLAIN always yields a
			// non-empty user, so an empty user here unambiguously means LOGIN.
			if user == "" && pass == "" {
				// First step: prompt for the username (334).
				if err := writeLine(w, "334 VXNlcm5hbWU6\r\n"); err != nil {
					return
				}
				uline, err := readLine(r, 8192)
				if err != nil {
					return
				}
				udec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(uline))
				if err != nil {
					// Invalid base64 username: fail auth.
					if err := writeLine(w, "501 Invalid base64\r\n"); err != nil {
						return
					}
					continue
				}
				user = string(udec)
				// Second step: prompt for the password (334).
				if err := writeLine(w, "334 UGFzc3dvcmQ6\r\n"); err != nil {
					return
				}
				pline, err := readLine(r, 8192)
				if err != nil {
					return
				}
				pdec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pline))
				if err != nil {
					if err := writeLine(w, "501 Invalid base64\r\n"); err != nil {
						return
					}
					continue
				}
				pass = string(pdec)
			}
			client := ""
			if s.auth != nil {
				client = s.auth.Validate(user, pass)
			}
			if client == "" {
				if err := writeLine(w, "535 Authentication failed\r\n"); err != nil {
					return
				}
				continue
			}
			authUser = client
			if err := writeLine(w, "235 Authentication successful\r\n"); err != nil {
				return
			}

		case cmd == "MAIL" || strings.HasPrefix(cmd, "MAIL "):
			// Fail-closed: refuse mail unless the client authenticated.
			if authUser == "" {
				if err := writeLine(w, "530 Authentication required\r\n"); err != nil {
					return
				}
				continue
			}
			// Reset the transaction (RFC 5321: a new MAIL starts fresh).
			to, body = nil, strings.Builder{}
			from = parsePath(arg)
			if from == "" {
				if err := writeLine(w, "501 Syntax error in parameters\r\n"); err != nil {
					return
				}
				continue
			}
			if err := writeLine(w, "250 OK\r\n"); err != nil {
				return
			}

		case cmd == "RCPT" || strings.HasPrefix(cmd, "RCPT "):
			if authUser == "" || from == "" {
				if err := writeLine(w, "503 Bad sequence\r\n"); err != nil {
					return
				}
				continue
			}
			rcpt := parsePath(arg)
			if rcpt == "" {
				if err := writeLine(w, "501 Syntax error in parameters\r\n"); err != nil {
					return
				}
				continue
			}
			to = append(to, rcpt)
			if err := writeLine(w, "250 OK\r\n"); err != nil {
				return
			}

		case cmd == "DATA" || cmd == "DATA ":
			if authUser == "" || from == "" || len(to) == 0 {
				if err := writeLine(w, "503 Bad sequence\r\n"); err != nil {
					return
				}
				continue
			}
			if err := writeLine(w, "354 End data with <CR><LF>.<CR><LF>\r\n"); err != nil {
				return
			}
			msg, err := readData(r, s.maxBytes)
			if err != nil {
				if err := writeLine(w, "451 Error processing\r\n"); err != nil {
					return
				}
				continue
			}
			body.Reset()
			body.WriteString(msg)
			// Parse headers (up to the blank line) from the DATA body.
			headers, bodyText := splitHeaders(msg)
			relay := RelayMessage{From: from, To: to, Subject: headers["Subject"], Body: bodyText, Headers: headers}
			code, resp := s.deliver.Deliver(s.ctx, authUser, relay)
			if err := writeLine(w, fmt.Sprintf("%d %s\r\n", code, resp)); err != nil {
				return
			}
			// Transaction complete; reset for the next message.
			from, to, body = "", nil, strings.Builder{}

		case cmd == "QUIT" || cmd == "QUIT ":
			_ = writeLine(w, "221 Bye\r\n")
			return

		case cmd == "RSET" || cmd == "RSET ":
			from, to, body = "", nil, strings.Builder{}
			if err := writeLine(w, "250 OK\r\n"); err != nil {
				return
			}

		case cmd == "NOOP" || cmd == "NOOP ":
			if err := writeLine(w, "250 OK\r\n"); err != nil {
				return
			}

		case cmd == "HELP" || cmd == "HELP ":
			if err := writeLine(w, "502 Command not implemented\r\n"); err != nil {
				return
			}

		default:
			if err := writeLine(w, "502 Command not implemented\r\n"); err != nil {
				return
			}
		}
	}
}

// writeEHLO emits the EHLO response. It advertises AUTH PLAIN and AUTH LOGIN
// when the client is not yet authenticated (so it can authenticate), and
// advertises SIZE + 8BITMIME always.
func writeEHLO(w *bufio.Writer, authed bool) error {
	if err := writeLine(w, "250-smtp.harmonicr.com\r\n"); err != nil {
		return err
	}
	if err := writeLine(w, "250-SIZE 26214400\r\n"); err != nil {
		return err
	}
	if err := writeLine(w, "250-8BITMIME\r\n"); err != nil {
		return err
	}
	if !authed {
		if err := writeLine(w, "250-AUTH PLAIN LOGIN\r\n"); err != nil {
			return err
		}
	}
	if err := writeLine(w, "250 PIPELINING\r\n"); err != nil {
		return err
	}
	return nil
}

// writeLine writes a CRLF-terminated line and returns only the error (the
// byte count is irrelevant to the SMTP protocol state machine).
func writeLine(w *bufio.Writer, s string) error {
	_, err := w.WriteString(s)
	if err != nil {
		return err
	}
	return w.Flush()
}

// parseAuth parses an AUTH argument. Supported: PLAIN <base64> and LOGIN.
// PLAIN decodes the full credentials (authzid\0user\0pass) in one line. LOGIN
// is two-step: this returns (user="", pass="", ok=true) with the LOGIN
// mechanism so the caller challenges for username then password. The caller
// distinguishes LOGIN from PLAIN by the empty user/pass returned (PLAIN
// always yields at least a non-empty user). It returns ok=false for an
// unrecognized mechanism or malformed base64.
func parseAuth(arg string) (user, pass string, ok bool) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return "", "", false
	}
	mech := strings.ToUpper(fields[0])
	switch mech {
	case "PLAIN":
		if len(fields) < 2 {
			return "", "", false
		}
		dec, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(dec), "\x00", 3)
		if len(parts) != 3 {
			return "", "", false
		}
		return parts[1], parts[2], true
	case "LOGIN":
		// Two-step: username and password are challenged separately.
		return "", "", true
	}
	return "", "", false
}

// parsePath extracts the address from a MAIL FROM:/RCPT TO: argument,
// handling the optional "<...>" brackets and source-route prefixes.
func parsePath(arg string) string {
	a := strings.TrimSpace(arg)
	a = strings.TrimPrefix(a, "FROM:")
	a = strings.TrimPrefix(a, "TO:")
	// Strip source route (<...>@) if present.
	if i := strings.Index(a, "<"); i >= 0 {
		a = a[i:]
	}
	if strings.HasPrefix(a, "<") {
		if j := strings.Index(a, ">"); j >= 0 {
			a = a[1:j]
		} else {
			return ""
		}
	}
	a = strings.TrimSpace(a)
	if a == "" || strings.ContainsAny(a, "\r\n") {
		return ""
	}
	return a
}

// readLine reads one CRLF-terminated line, enforcing a max length.
func readLine(r *bufio.Reader, max int) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > max {
		return "", fmt.Errorf("line too long")
	}
	return line, nil
}

// readData reads the message body until a line consisting of exactly "."
// (dot-stuffing handled: a leading ".." becomes "."). It enforces maxBytes.
func readData(r *bufio.Reader, max int64) (string, error) {
	var sb strings.Builder
	var n int64
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			break
		}
		// Dot-stuffing: ".." at the start of a line becomes a single ".".
		if strings.HasPrefix(trimmed, "..") {
			trimmed = trimmed[1:]
		}
		n += int64(len(trimmed)) + 2
		if n > max {
			return "", fmt.Errorf("message too large")
		}
		sb.WriteString(trimmed)
		sb.WriteString("\r\n")
	}
	return sb.String(), nil
}

// splitHeaders separates MIME headers from the body. The first blank line
// ends the headers; everything after is the body. Subject is pulled from the
// headers. Returns the header map and the body text.
func splitHeaders(data string) (map[string]string, string) {
	headers := map[string]string{}
	// Normalize: headers end at the first blank line.
	idx := strings.Index(data, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(data, "\n\n")
	}
	var head, body string
	if idx < 0 {
		head, body = data, ""
	} else {
		head, body = data[:idx], data[idx:]
	}
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Continuation lines (folded) are appended to the previous header.
		if line[0] == ' ' || line[0] == '\t' {
			// Append to the last header value (ignored for routing).
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		headers[name] = val
	}
	body = strings.TrimPrefix(body, "\r\n")
	body = strings.TrimPrefix(body, "\n")
	return headers, body
}

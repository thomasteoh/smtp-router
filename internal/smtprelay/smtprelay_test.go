package smtprelay

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
)

// testAuth is a trivial Authenticator that accepts a fixed user/pass pair.
type testAuth struct {
	user, pass string
}

func (t testAuth) Validate(user, pass string) string {
	if user == t.user && pass == t.pass {
		return user
	}
	return ""
}

// testDeliver is a trivial Deliverer that records the message and returns a
// configurable code.
type testDeliver struct {
	code int
	msg  string
	got  RelayMessage
}

func (t *testDeliver) Deliver(ctx context.Context, client string, msg RelayMessage) (int, string) {
	t.got = msg
	if t.msg != "" {
		return t.code, t.msg
	}
	return t.code, "ok"
}

// startServer starts a relay on an ephemeral port and returns the addr.
func startServer(t *testing.T, auth Authenticator, deliver Deliverer) string {
	t.Helper()
	s := New(Config{
		Addr:    "127.0.0.1:0",
		Auth:    auth,
		Deliver: deliver,
		Timeout: 10 * time.Second,
	})
	if err := s.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = s.Close()
	})
	return s.Addr()
}

// dial opens a TCP connection and returns the buffered reader/writer.
func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	// Read the 220 greeting.
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("expected 220, got %q", line)
	}
	return c, r, w
}

func sendLine(t *testing.T, w *bufio.Writer, line string) {
	t.Helper()
	_, err := w.WriteString(line + "\r\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Flush()
}

func readResp(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func TestRequiresAuthBeforeMail(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	// EHLO (no auth).
	sendLine(t, w, "EHLO test")
	// Read all multiline responses.
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("unexpected EHLO response: %q", line)
		}
	}

	// MAIL without AUTH must be refused.
	sendLine(t, w, "MAIL FROM:<noreply@harmonicr.com>")
	line := readResp(t, r)
	if !strings.HasPrefix(line, "530") {
		t.Fatalf("expected 530 Authentication required, got %q", line)
	}
}

func TestAuthThenDeliver(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	// EHLO.
	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// AUTH PLAIN.
	creds := base64.StdEncoding.EncodeToString([]byte("\x00zulip\x00secret"))
	sendLine(t, w, "AUTH PLAIN "+creds)
	line := readResp(t, r)
	if !strings.HasPrefix(line, "235") {
		t.Fatalf("expected 235, got %q", line)
	}

	// MAIL FROM.
	sendLine(t, w, "MAIL FROM:<noreply@harmonicr.com>")
	line = readResp(t, r)
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("expected 250 MAIL, got %q", line)
	}

	// RCPT TO.
	sendLine(t, w, "RCPT TO:<someone@harmonicr.com>")
	line = readResp(t, r)
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("expected 250 RCPT, got %q", line)
	}

	// DATA.
	sendLine(t, w, "DATA")
	line = readResp(t, r)
	if !strings.HasPrefix(line, "354") {
		t.Fatalf("expected 354 DATA, got %q", line)
	}

	// Message body + terminator.
	body := "Subject: hello\r\n\r\nThis is the body.\r\n.\r\n"
	_, err := w.WriteString(body)
	if err != nil {
		t.Fatalf("write body: %v", err)
	}
	_ = w.Flush()

	line = readResp(t, r)
	if !strings.HasPrefix(line, "250") {
		t.Fatalf("expected 250 after DATA, got %q", line)
	}
	if d.got.From == "" {
		t.Fatal("deliver not called")
	}
	if d.got.From != "noreply@harmonicr.com" {
		t.Fatalf("from = %q", d.got.From)
	}
	if len(d.got.To) != 1 || d.got.To[0] != "someone@harmonicr.com" {
		t.Fatalf("to = %v", d.got.To)
	}
	if d.got.Subject != "hello" {
		t.Fatalf("subject = %q", d.got.Subject)
	}
	if !strings.Contains(d.got.Body, "This is the body.") {
		t.Fatalf("body = %q", d.got.Body)
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	creds := base64.StdEncoding.EncodeToString([]byte("\x00zulip\x00wrong"))
	sendLine(t, w, "AUTH PLAIN "+creds)
	line := readResp(t, r)
	if !strings.HasPrefix(line, "535") {
		t.Fatalf("expected 535, got %q", line)
	}
}

func TestUnknownCommand(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "FOO bar")
	line := readResp(t, r)
	if !strings.HasPrefix(line, "502") {
		t.Fatalf("expected 502, got %q", line)
	}
}

func TestDotStuffing(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	creds := base64.StdEncoding.EncodeToString([]byte("\x00zulip\x00secret"))
	sendLine(t, w, "AUTH PLAIN "+creds)
	_ = readResp(t, r)
	sendLine(t, w, "MAIL FROM:<noreply@harmonicr.com>")
	_ = readResp(t, r)
	sendLine(t, w, "RCPT TO:<x@harmonicr.com>")
	_ = readResp(t, r)
	sendLine(t, w, "DATA")
	_ = readResp(t, r)

	// Dot-stuffed line: a leading ".." becomes ".". Terminator is ".\r\n".
	body := "Subject: x\r\n\r\n..a leading dot\r\n.\r\n"
	_, err := w.WriteString(body)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Flush()
	_ = readResp(t, r)

	if d.got.From == "" {
		t.Fatal("deliver not called")
	}
	if !strings.Contains(d.got.Body, ".a leading dot") {
		t.Fatalf("dot-stuffed body = %q", d.got.Body)
	}
}

func TestParseAuthPlain(t *testing.T) {
	// PLAIN with authzid.
	enc := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	u, p, ok := parseAuth("PLAIN " + enc)
	if !ok || u != "user" || p != "pass" {
		t.Fatalf("got %q %q %v", u, p, ok)
	}
}

func TestAuthLoginTwoStep(t *testing.T) {
	// AUTH LOGIN is two-step: 334 username, 334 password, 235 success.
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	sendLine(t, w, "AUTH LOGIN")
	if l := readResp(t, r); !strings.HasPrefix(l, "334") {
		t.Fatalf("username challenge = %q, want 334", l)
	}
	sendLine(t, w, base64.StdEncoding.EncodeToString([]byte("zulip")))
	if l := readResp(t, r); !strings.HasPrefix(l, "334") {
		t.Fatalf("password challenge = %q, want 334", l)
	}
	sendLine(t, w, base64.StdEncoding.EncodeToString([]byte("secret")))
	if l := readResp(t, r); !strings.HasPrefix(l, "235") {
		t.Fatalf("success = %q, want 235", l)
	}
}

func TestAuthLoginWrongPass(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	sendLine(t, w, "AUTH LOGIN")
	readResp(t, r) // 334 username
	sendLine(t, w, base64.StdEncoding.EncodeToString([]byte("zulip")))
	readResp(t, r) // 334 password
	sendLine(t, w, base64.StdEncoding.EncodeToString([]byte("wrong")))
	if l := readResp(t, r); !strings.HasPrefix(l, "535") {
		t.Fatalf("wrong pass = %q, want 535", l)
	}
}

func TestAuthLoginInvalidBase64(t *testing.T) {
	auth := testAuth{user: "zulip", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	sendLine(t, w, "AUTH LOGIN")
	readResp(t, r) // 334 username
	sendLine(t, w, "not-base64!!")
	if l := readResp(t, r); !strings.HasPrefix(l, "501") {
		t.Fatalf("invalid base64 = %q, want 501", l)
	}
}

func TestParseMIMEBodyMultipartAlternative(t *testing.T) {
	// A multipart/alternative email (the form Zitadel/Gmail send): plain text
	// + HTML. The relay must extract the HTML part, not pass the raw MIME.
	headers := map[string]string{
		"Content-Type": `multipart/alternative; boundary="b0und4ry"`,
	}
	body := "--b0und4ry\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Plain text body here\r\n" +
		"--b0und4ry\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body><p>Hello <b>world</b></p></body></html>\r\n" +
		"--b0und4ry--\r\n"
	plain, html := parseMIMEBody(headers, body)
	if !strings.Contains(plain, "Plain text body here") {
		t.Fatalf("plain = %q, want the plain-text part", plain)
	}
	if !strings.Contains(html, "<p>Hello <b>world</b></p>") {
		t.Fatalf("html = %q, want the HTML part (no boundary markers)", html)
	}
	if strings.Contains(html, "b0und4ry") || strings.Contains(html, "Content-Type:") {
		t.Fatalf("html = %q, must not contain MIME boundary/markers", html)
	}
}

func TestParseMIMEBodyQuotedPrintable(t *testing.T) {
	// The HTML part is quoted-printable encoded; the relay must decode it.
	headers := map[string]string{
		"Content-Type": `multipart/alternative; boundary="xyz"`,
	}
	body := "--xyz\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"plain\r\n" +
		"--xyz\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"<p>Hello=20world</p>\r\n" +
		"--xyz--\r\n"
	_, html := parseMIMEBody(headers, body)
	if !strings.Contains(html, "Hello world") {
		t.Fatalf("html = %q, want decoded quoted-printable (Hello world)", html)
	}
}

func TestParseMIMEBodyPlainOnly(t *testing.T) {
	// No Content-Type / no multipart: the body is plain text.
	headers := map[string]string{"Content-Type": "text/plain; charset=utf-8"}
	plain, html := parseMIMEBody(headers, "Just some text")
	if plain != "Just some text" || html != "" {
		t.Fatalf("plain=%q html=%q, want plain only", plain, html)
	}
}

func TestParseMIMEBodyBase64(t *testing.T) {
	// A base64-encoded HTML part is decoded.
	enc := base64.StdEncoding.EncodeToString([]byte("<p>Hello</p>"))
	headers := map[string]string{
		"Content-Type": `multipart/alternative; boundary="b"`,
	}
	body := "--b\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"plain\r\n" +
		"--b\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		enc + "\r\n" +
		"--b--\r\n"
	_, html := parseMIMEBody(headers, body)
	if !strings.Contains(html, "<p>Hello</p>") {
		t.Fatalf("html = %q, want decoded base64 HTML", html)
	}
}

func TestRelayDeliversHTML(t *testing.T) {
	// End-to-end: a multipart/alternative email over SMTP reaches the
	// deliverer with both the plain and HTML parts separated.
	auth := testAuth{user: "zitadel", pass: "secret"}
	d := &testDeliver{code: 250}
	addr := startServer(t, auth, d)
	c, r, w := dial(t, addr)
	defer c.Close()

	sendLine(t, w, "EHLO test")
	for {
		line := readResp(t, r)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	creds := base64.StdEncoding.EncodeToString([]byte("\x00zitadel\x00secret"))
	sendLine(t, w, "AUTH PLAIN "+creds)
	_ = readResp(t, r)
	sendLine(t, w, "MAIL FROM:<noreply@harmonicr.com>")
	_ = readResp(t, r)
	sendLine(t, w, "RCPT TO:<someone@harmonicr.com>")
	_ = readResp(t, r)
	sendLine(t, w, "DATA")
	_ = readResp(t, r)

	// A multipart/alternative message (HTML present).
	msg := "Subject: Verify\r\n" +
		"Content-Type: multipart/alternative; boundary=\"bb\"\r\n" +
		"\r\n" +
		"--bb\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Click the link to verify.\r\n" +
		"--bb\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<a href=\"https://x\">Verify</a>\r\n" +
		"--bb--\r\n" +
		".\r\n"
	_, err := w.WriteString(msg)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Flush()
	_ = readResp(t, r)

	if d.got.Body == "" || !strings.Contains(d.got.Body, "Click the link") {
		t.Fatalf("delivered Body = %q, want the plain part", d.got.Body)
	}
	if d.got.HTML == "" || !strings.Contains(d.got.HTML, "<a href=\"https://x\">Verify</a>") {
		t.Fatalf("delivered HTML = %q, want the HTML part", d.got.HTML)
	}
	if strings.Contains(d.got.HTML, "--bb") {
		t.Fatalf("delivered HTML = %q, must not contain MIME boundary", d.got.HTML)
	}
}

func TestParsePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"FROM:<a@b.com>", "a@b.com"},
		{"FROM:<a@b.com> SIZE=100", "a@b.com"},
		{"<a@b.com>", "a@b.com"},
		{"a@b.com", "a@b.com"},
		{"TO:<x@y.com>", "x@y.com"},
	}
	for _, c := range cases {
		if got := parsePath(c.in); got != c.want {
			t.Fatalf("parsePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

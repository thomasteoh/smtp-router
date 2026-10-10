package web

import (
	"html/template"
	"strings"
	"testing"
)

func TestIndexTemplateRenders(t *testing.T) {
	src := string(IndexHTML())
	page := template.Must(template.New("index").Parse(src))
	data := map[string]any{
		"Email":       "thomas@awry.com.au",
		"Name":        "Thomas Teoh",
		"Roles":       []string{"admin"},
		"AccessToken": "eyJhbG...NiJ9.acc.xyz",
	}
	var b strings.Builder
	if err := page.ExecuteTemplate(&b, "index", data); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "thomas@awry.com.au") {
		t.Fatalf("email not rendered")
	}
	if !strings.Contains(out, "smtp-router admin") {
		t.Fatalf("title not rendered")
	}
	if !strings.Contains(out, "eyJhbG...NiJ9.acc.xyz") {
		t.Fatalf("access token not embedded")
	}
	if strings.Contains(out, "IDTOKEN_REF") {
		t.Fatalf("ID token reference must not be embedded")
	}
	if !strings.Contains(out, "addProvider") {
		t.Fatalf("script missing")
	}
}

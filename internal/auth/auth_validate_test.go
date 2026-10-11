package auth

import "testing"

func TestValidateUserPass(t *testing.T) {
	a := New()
	key, err := a.Generate("zulip")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Correct pair.
	if got := a.ValidateUserPass("zulip", key); got != "zulip" {
		t.Fatalf("expected zulip, got %q", got)
	}
	// Wrong password.
	if got := a.ValidateUserPass("zulip", "wrong"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	// Wrong username.
	if got := a.ValidateUserPass("other", key); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	// Empty inputs.
	if got := a.ValidateUserPass("", ""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestValidateUserPassUnknownClient(t *testing.T) {
	a := New()
	if got := a.ValidateUserPass("nobody", "anything"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

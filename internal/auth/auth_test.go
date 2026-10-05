package auth

import "testing"

func TestGenerateAndValidate(t *testing.T) {
	a := New()
	key, err := a.Generate("client-a")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if key == "" {
		t.Fatal("empty key")
	}
	if got := a.Validate(key); got != "client-a" {
		t.Fatalf("validate = %q, want client-a", got)
	}
	if got := a.Validate("wrong-key"); got != "" {
		t.Fatalf("validate wrong = %q, want empty", got)
	}
}

func TestKeysAreUnique(t *testing.T) {
	a := New()
	k1, _ := a.Generate("c1")
	k2, _ := a.Generate("c2")
	if k1 == k2 {
		t.Fatal("keys should be unique")
	}
}

func TestAddLoadsConfigKey(t *testing.T) {
	a := New()
	a.Add("client-x", "known-secret")
	if got := a.Validate("known-secret"); got != "client-x" {
		t.Fatalf("validate = %q, want client-x", got)
	}
}

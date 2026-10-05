package oidc

import "testing"

func TestHasRoleZitadelShape(t *testing.T) {
	claims := map[string]any{
		"urn:zitadel:iam:org:project:roles": map[string]any{
			"mail-admin": map[string]any{"123456789012345678": "harmonicr"},
			"docs":       map[string]any{"123456789012345678": "harmonicr"},
		},
	}
	if !hasRole(claims, "mail-admin") {
		t.Fatal("expected mail-admin role present")
	}
	if hasRole(claims, "nonexistent") {
		t.Fatal("expected nonexistent role absent")
	}
}

func TestHasRoleFlatFallback(t *testing.T) {
	claims := map[string]any{
		"roles": []any{"mail-admin", "docs"},
	}
	if !hasRole(claims, "mail-admin") {
		t.Fatal("expected flat roles fallback to find mail-admin")
	}
	if hasRole(claims, "other") {
		t.Fatal("expected other absent")
	}
}

func TestHasRoleEmptyGateAllows(t *testing.T) {
	// No admin role configured → no gate, allow.
	if !hasRole(map[string]any{}, "") {
		t.Fatal("empty role should allow")
	}
}

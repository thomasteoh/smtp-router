package rules

import "testing"

func TestAllowDomainPattern(t *testing.T) {
	r := New([]string{"*@harmonicr.com"}, nil)
	if err := r.Check("alerts@harmonicr.com"); err != nil {
		t.Fatalf("should allow domain pattern: %v", err)
	}
	if err := r.Check("noreply@harmonicr.com"); err != nil {
		t.Fatalf("should allow domain pattern: %v", err)
	}
	if err := r.Check("user@example.com"); err == nil {
		t.Fatal("should deny non-allowed domain")
	}
}

func TestDenyList(t *testing.T) {
	r := New([]string{"*@harmonicr.com"}, []string{"noreply@harmonicr.com"})
	if err := r.Check("noreply@harmonicr.com"); err == nil {
		t.Fatal("denylist should win")
	}
	if err := r.Check("alerts@harmonicr.com"); err != nil {
		t.Fatalf("should allow non-denied: %v", err)
	}
}

func TestExactAllow(t *testing.T) {
	r := New([]string{"alerts@harmonicr.com"}, nil)
	if err := r.Check("alerts@harmonicr.com"); err != nil {
		t.Fatalf("should allow exact: %v", err)
	}
	if err := r.Check("other@harmonicr.com"); err == nil {
		t.Fatal("should deny non-listed address")
	}
}

// TestFailClosedEmptyAllowlist verifies an empty allowlist denies everything
// (the router must not become an open relay when no allow rules are set).
func TestFailClosedEmptyAllowlist(t *testing.T) {
	r := New(nil, nil)
	if err := r.Check("alerts@harmonicr.com"); err == nil {
		t.Fatal("empty allowlist must deny all senders (fail closed)")
	}
	r = New([]string{}, nil)
	if err := r.Check("alerts@harmonicr.com"); err == nil {
		t.Fatal("empty allowlist must deny all senders (fail closed)")
	}
}

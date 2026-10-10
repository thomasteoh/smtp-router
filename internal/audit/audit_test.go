package audit

import (
	"testing"
)

// TestListEmptyEmitsEmptyArray verifies an empty audit log returns an empty
// (non-nil) slice, so JSON marshals to [] not null (the web console iterates
// the response and would throw on null).
func TestListEmptyEmitsEmptyArray(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	rows, err := s.List(50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if rows == nil {
		t.Fatal("List returned nil slice; want empty non-nil slice (JSON must emit [])")
	}
	if len(rows) != 0 {
		t.Fatalf("len = %d, want 0", len(rows))
	}
}

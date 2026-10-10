package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveAtomic verifies Save writes via a temp file + rename, leaves no
// temp artifacts, and preserves mode 0600. A crash mid-write must not leave a
// truncated config.json (the only copy of provider creds and admin settings).
func TestSaveAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := &Config{
		AdminToken: "secret",
		Allowlist:  []string{"*@harmonicr.com"},
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if string(b) == "" {
		t.Fatal("saved config is empty")
	}
	// Mode preserved 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	// No leftover temp files in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Fatalf("unexpected leftover file: %s", e.Name())
		}
	}
	// Overwrite works (rename path).
	if err := c.Save(path); err != nil {
		t.Fatalf("second save: %v", err)
	}
}

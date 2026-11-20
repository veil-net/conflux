package flock

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHeldRefusesAReparsePoint: the lock lives where anchord's own account can write, so a
// symbolic link there is refused rather than asked through to whatever it names.
func TestHeldRefusesAReparsePoint(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(t.TempDir(), "serve.lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := Held(link); err == nil {
		t.Error("a symbolic link was asked through")
	}
}

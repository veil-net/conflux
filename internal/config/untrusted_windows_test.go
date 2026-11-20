package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadUntrustedRefusesAReparsePoint: a symbolic link in a directory the account can write
// is not followed, so SYSTEM reading it cannot be turned into SYSTEM reading whatever the
// account pointed it at.
func TestReadUntrustedRefusesAReparsePoint(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "subnets.json")
	if err := os.WriteFile(ok, []byte(`{"subnets": []}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if b, err := ReadUntrusted(ok, 1<<20); err != nil || string(b) != `{"subnets": []}` {
		t.Errorf("ReadUntrusted = %q, %v", b, err)
	}

	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("SYSTEM's"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	if b, err := ReadUntrusted(link, 1<<20); err == nil {
		t.Errorf("a symbolic link was followed: %q", b)
	}
}

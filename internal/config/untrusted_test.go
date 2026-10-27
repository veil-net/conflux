//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReadUntrusted: a file the account could have made anything of is read only when it
// is one regular file of its own, under the size asked.
func TestReadUntrusted(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "subnets.json")
	if err := os.WriteFile(ok, []byte(`{"subnets": []}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if b, err := ReadUntrusted(ok, 1<<20); err != nil || string(b) != `{"subnets": []}` {
		t.Errorf("ReadUntrusted = %q, %v", b, err)
	}

	if _, err := ReadUntrusted(ok, 4); err == nil {
		t.Error("a file past the size asked was read")
	}

	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	hard := filepath.Join(dir, "hard")
	if err := os.Link(secret, hard); err != nil {
		t.Fatal(err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{link, hard, fifo} {
		if b, err := ReadUntrusted(path, 1<<20); err == nil {
			t.Errorf("%s was read: %q", filepath.Base(path), b)
		}
	}
}

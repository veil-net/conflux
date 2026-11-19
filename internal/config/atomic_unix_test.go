//go:build unix

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteFileAtomicSetsTheModeItIsGiven: each mode a writer asks for -- a secret's 0600,
// and the 0644, 0755 and 0555 of the boot services' definitions -- whatever the umask. Under
// 077 the temporary file is created 0600 whatever is asked, so only the chmod on its
// descriptor makes the wider ones.
func TestWriteFileAtomicSetsTheModeItIsGiven(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()

	for _, perm := range []fs.FileMode{0o600, 0o644, 0o755, 0o555} {
		path := filepath.Join(dir, perm.String())

		if err := WriteFileAtomic(path, []byte("seed"), perm); err != nil {
			t.Fatalf("WriteFileAtomic %o: %v", perm, err)
		}

		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}

		if got := fi.Mode().Perm(); got != perm {
			t.Errorf("mode = %o under umask 077, want %o", got, perm)
		}
	}
}

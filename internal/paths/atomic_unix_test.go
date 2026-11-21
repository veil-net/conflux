//go:build unix

package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteAtomicSetsTheModeItIsGiven: each mode a writer asks for -- a secret's 0600,
// and the 0644, 0755 and 0555 of the boot services' definitions -- whatever the umask. Under
// 077 the temporary file is created 0600 whatever is asked, so only the chmod on its
// descriptor makes the wider ones.
func TestWriteAtomicSetsTheModeItIsGiven(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()

	for _, perm := range []fs.FileMode{0o600, 0o644, 0o755, 0o555} {
		path := filepath.Join(dir, perm.String())

		if err := WriteAtomic(path, perm, -1, -1, []byte("seed")); err != nil {
			t.Fatalf("WriteAtomic %o: %v", perm, err)
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

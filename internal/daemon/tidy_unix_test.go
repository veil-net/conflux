//go:build !windows

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// widen makes path readable by everybody, as a hand's chmod might.
func widen(t *testing.T, path string) {
	t.Helper()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// restored reports whether path is the supervisor's alone again: at mode, the mode it has on Unix.
func restored(path string, mode os.FileMode) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.Mode().Perm() == mode
}

// stuck makes the entry at path one removeExcept cannot remove, through removeEntry: a test run
// as root removes whatever it likes, so nothing on disk could.
func stuck(t *testing.T, path string) {
	t.Helper()

	name := filepath.Base(path)

	removeEntry = func(r *os.Root, n string) error {
		if n == name {
			return &fs.PathError{Op: "unlinkat", Path: n, Err: syscall.EBUSY}
		}

		return r.RemoveAll(n)
	}

	t.Cleanup(func() { removeEntry = (*os.Root).RemoveAll })
}

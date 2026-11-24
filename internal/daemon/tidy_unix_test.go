//go:build !windows

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestTidyPutsTheRootsFilesBackToTheirModes: what the root holds is the supervisor's and
// 0600, the copy of conflux the service runs 0700, whatever somebody changed them to.
func TestTidyPutsTheRootsFilesBackToTheirModes(t *testing.T) {
	s := &Supervisor{Dirs: dirs(t)}
	d := s.Dirs

	for path, want := range map[string]os.FileMode{
		d.ManifestFile(): 0o600, d.ConfigFile(): 0o600, d.StateFile(): 0o600, d.ServiceExecutable(): 0o700,
	} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}

		defer func(path string, want os.FileMode) {
			fi, err := os.Stat(path)
			if err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s is %v after tidy (%v), want %#o", path, fi.Mode().Perm(), err, want)
			}
		}(path, want)
	}

	if err := s.tidyRoot(); err != nil {
		t.Fatal(err)
	}
}

// widen makes path readable by everybody, as a hand's chmod might.
func widen(t *testing.T, path string) {
	t.Helper()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// restored reports whether path is the supervisor's alone again: 0600.
func restored(path string) bool {
	fi, err := os.Stat(path)

	return err == nil && fi.Mode().Perm() == 0o600
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

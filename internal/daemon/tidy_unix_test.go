//go:build !windows

package daemon

import (
	"os"
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

	if err := s.tidy(); err != nil {
		t.Fatal(err)
	}
}

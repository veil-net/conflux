package daemon

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// TestTidyGivesTheRootsFilesBackToTheAdministrators: on Windows the root's own files are
// SYSTEM's and the Administrators' again at a start, as on Unix they get their modes back,
// whatever was granted on them since: a grant to Users on the configuration, and on the copy
// of conflux the service runs, is taken back.
func TestTidyGivesTheRootsFilesBackToTheAdministrators(t *testing.T) {
	s := &Supervisor{Dirs: dirs(t)}
	d := s.Dirs

	files := []string{d.ConfigFile(), d.ServiceExecutable()}

	for _, path := range files {
		if err := config.WriteFileAtomic(path, []byte("conflux's"), 0o600); err != nil {
			t.Fatal(err)
		}

		widen(t, path)
	}

	if err := s.tidyRoot(); err != nil {
		t.Fatal(err)
	}

	for _, path := range files {
		if !restored(path) {
			t.Errorf("%s still grants Users, or belongs to another account, after the root was tidied", path)
		}
	}
}

// widen grants Users read access to path, as somebody might since.
func widen(t *testing.T, path string) {
	t.Helper()

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}

	if err := grantSID(path, users, windows.FILE_GENERIC_READ); err != nil {
		t.Fatal(err)
	}

	if paths.OnlyAdmins(path) {
		t.Fatalf("%s, granted to Users, reads as SYSTEM's and the Administrators' alone", path)
	}
}

// restored reports whether path is SYSTEM's and the Administrators' alone again.
func restored(path string) bool { return paths.OnlyAdmins(path) }

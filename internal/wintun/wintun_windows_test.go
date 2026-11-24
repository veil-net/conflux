package wintun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// TestTheDriverIsRemovedThroughAnySetsLibrary: uninstall may be run by a conflux whose pair is
// not the one the supervisor extracted -- an upgrade not yet restarted onto, or a placeholder
// build -- and the library in the supervisor's set removes the driver as well as one in its
// own would.
func TestTheDriverIsRemovedThroughAnySetsLibrary(t *testing.T) {
	d := paths.Dirs{Root: t.TempDir()}

	if got := driverLibrary(d); got != "" {
		t.Errorf("driverLibrary found %s in a root with no bin directory", got)
	}

	set := filepath.Join(d.Libexec(), "0123456789abcdef")
	if err := os.MkdirAll(set, 0o700); err != nil {
		t.Fatal(err)
	}

	if got := driverLibrary(d); got != "" {
		t.Errorf("driverLibrary found %s in a set with no library", got)
	}

	want := filepath.Join(set, DLLName)
	if err := os.WriteFile(want, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := driverLibrary(d); got != want {
		t.Errorf("driverLibrary = %q, want the library in another build's set, %s", got, want)
	}
}

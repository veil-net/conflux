package paths

import (
	"path/filepath"
	"testing"
)

// TestExecutableLooksAboveARootNotMadeYet: a root that does not exist yet is judged by the
// filesystem it would be made on.
func TestExecutableLooksAboveARootNotMadeYet(t *testing.T) {
	ok, err := executable(filepath.Join(t.TempDir(), "not", "made", "yet"))
	if err != nil {
		t.Fatal(err)
	}

	// The test's own directory is where `go test` ran this binary from, so it allows exec.
	if !ok {
		t.Error("a root under the test's own directory reads as noexec")
	}
}

// TestTheRootsConfluxMakesPassTheReadersCheck: a reader holds every root to Check, so the installation's
// root EnsureAll makes passes it, on every platform.
func TestTheRootsConfluxMakesPassTheReadersCheck(t *testing.T) {
	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	if err := d.Check(); err != nil {
		t.Errorf("Check(the installation's root, which EnsureAll made) = %v", err)
	}
}

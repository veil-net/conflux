package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestEphemeralCandidatesAreNotTheMachines: an ephemeral run is kept apart from the
// installation, never in or under the machine's .conflux, so it touches nothing of it.
func TestEphemeralCandidatesAreNotTheMachines(t *testing.T) {
	for _, c := range EphemeralCandidates() {
		if rel, err := filepath.Rel(platformRoot(), c); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("the ephemeral root %s is inside the machine's %s", c, platformRoot())
		}
	}
}

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

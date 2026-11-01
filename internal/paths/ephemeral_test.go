package paths

import (
	"path/filepath"
	"testing"
)

// TestEphemeralRootIsInsideCONFLUXDIR: a run rooted elsewhere keeps its ephemeral root
// inside that root and nowhere else, so a test, or a second installation, never touches the
// machine's own.
func TestEphemeralRootIsInsideCONFLUXDIR(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONFLUX_DIR", root)

	if got := EphemeralCandidates(); len(got) != 1 || got[0] != filepath.Join(root, "ephemeral") {
		t.Fatalf("EphemeralCandidates() = %v, want only %s", got, filepath.Join(root, "ephemeral"))
	}

	d, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(root, "ephemeral")
	if d.State != want || d.Config != want || d.Run != filepath.Join(want, "run") || d.Log != "" {
		t.Errorf("Ephemeral() = %+v, want everything in %s and no log directory", d, want)
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

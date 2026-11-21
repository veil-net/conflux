package paths

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// TestEphemeralRootIsInsideCONFLUXDIR: a run rooted elsewhere keeps its ephemeral root inside that
// root's DirName and nowhere else, so a test, or a second installation, never touches the machine's
// own, nor the CONFLUX_DIR itself.
func TestEphemeralRootIsInsideCONFLUXDIR(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONFLUX_DIR", root)

	want := filepath.Join(root, DirName, "ephemeral")

	if got := EphemeralCandidates(); len(got) != 1 || got[0] != want {
		t.Fatalf("EphemeralCandidates() = %v, want only %s", got, want)
	}

	d, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}

	if d.State != want || d.Config != want || d.Run != filepath.Join(want, "run") || d.Log != "" {
		t.Errorf("Ephemeral() = %+v, want everything in %s and no log directory", d, want)
	}
}

// TestFirstExecutableSaysWhyItRefused: where every candidate is refused, the first refusal is
// the answer, not ErrNoExec, which would send the user to their mount options for a directory
// another account made.
func TestFirstExecutableSaysWhyItRefused(t *testing.T) {
	first, second := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	refusal := errors.New(first + " belongs to another account")

	_, err := FirstExecutable([]string{first, second}, func(c string) error {
		if c == first {
			return refusal
		}

		return errors.New(c + " belongs to another account too")
	})
	if !errors.Is(err, refusal) {
		t.Errorf("FirstExecutable with every candidate refused = %v, want the first refusal", err)
	}
}

// TestANoexecRefusalNeverHidesTheRealOne: a candidate refused for its filesystem alone (ErrNoExec) is
// passed over as one on a noexec filesystem is, so a later candidate's refusal for anything else is the
// answer, and not "every place is noexec", which would send the user to their mount options for a
// candidate that failed for another reason.
func TestANoexecRefusalNeverHidesTheRealOne(t *testing.T) {
	first, second := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	refusal := errors.New(second + " could not be removed")

	_, err := FirstExecutable([]string{first, second}, func(c string) error {
		if c == first {
			return fmt.Errorf("%s is on a filesystem mounted noexec: %w", c, ErrNoExec)
		}

		return refusal
	})
	if !errors.Is(err, refusal) || errors.Is(err, ErrNoExec) {
		t.Errorf("FirstExecutable, the first candidate noexec and the second refused = %v, want the second's refusal",
			err)
	}

	if _, err := FirstExecutable([]string{first}, func(c string) error {
		return fmt.Errorf("%s is on a filesystem mounted noexec: %w", c, ErrNoExec)
	}); !errors.Is(err, ErrNoExec) {
		t.Errorf("FirstExecutable, every candidate noexec = %v, want %v", err, ErrNoExec)
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

// TestTheRootsConfluxMakesPassTheReadersCheck: a reader holds every root to Check, so each root
// EnsureAll makes passes it, on every platform: a CONFLUX_DIR installation's, the ephemeral root inside
// it, and an ephemeral root of the platform's kind, outside any CONFLUX_DIR.
func TestTheRootsConfluxMakesPassTheReadersCheck(t *testing.T) {
	passes := func(d Dirs, what string) {
		t.Helper()

		if err := d.EnsureAll(); err != nil {
			t.Fatalf("EnsureAll(%s): %v", what, err)
		}

		if err := d.Check(); err != nil {
			t.Errorf("Check(%s, which EnsureAll made) = %v", what, err)
		}
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	passes(Default(), "a CONFLUX_DIR installation's root")

	inside, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}

	passes(inside, "the ephemeral root inside it")

	t.Setenv("CONFLUX_DIR", "")

	passes(EphemeralDirs(filepath.Join(t.TempDir(), ephemeralName)), "an ephemeral root outside any CONFLUX_DIR")
}

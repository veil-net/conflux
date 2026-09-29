package anchorctl

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnErrorSaysWhyNothingRan: an anchorctl that never started writes nothing to
// stderr, and an exit code of -1 is not a reason. The error has to carry the run's own
// -- a failed exec on Unix, a failed lookup on Windows -- and not read as an exit.
func TestAnErrorSaysWhyNothingRan(t *testing.T) {
	c := &Ctl{Bin: filepath.Join(t.TempDir(), "anchorctl")}

	_, err := c.Status(t.Context())
	if err == nil {
		t.Fatal("Status succeeded with no binary to run")
	}

	var e *Error
	if !errors.As(err, &e) || e.Err == nil {
		t.Fatalf("the error carries no reason: %v", err)
	}

	if exit := new(exec.ExitError); errors.As(err, &exit) || strings.Contains(err.Error(), "exit status") {
		t.Errorf("a binary that never started reads as an exit: %v", err)
	}
}

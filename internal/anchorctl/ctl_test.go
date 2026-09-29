package anchorctl

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnErrorSaysWhyNothingRan: an anchorctl that never started writes nothing to
// stderr, and an exit code of -1 is not a reason. The error has to carry the run's own.
func TestAnErrorSaysWhyNothingRan(t *testing.T) {
	c := &Ctl{Bin: filepath.Join(t.TempDir(), "anchorctl")}

	_, err := c.Status(t.Context())
	if err == nil {
		t.Fatal("Status succeeded with no binary to run")
	}

	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the error does not unwrap to the missing binary: %v", err)
	}

	if !strings.Contains(err.Error(), "anchorctl status: ") || strings.Contains(err.Error(), "exit status") {
		t.Errorf("the error names no reason: %v", err)
	}
}

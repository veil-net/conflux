package anchorctl_test

import (
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// TestMain roots every conflux path in a directory of the run's own before any test starts,
// so a test that does not root its own reaches nothing of the machine's .conflux.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "conflux-test-")
	if err != nil {
		panic(err)
	}

	restore := paths.UseRoot(dir)
	code := m.Run()

	restore()
	_ = os.RemoveAll(dir)

	os.Exit(code)
}

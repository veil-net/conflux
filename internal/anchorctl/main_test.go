package anchorctl_test

import (
	"testing"

	"github.com/veil-net/conflux/internal/paths/pathstest"
)

// TestMain roots every conflux path in a directory of the run's own before any test starts,
// so a test that does not root its own reaches nothing of the machine's .conflux.
func TestMain(m *testing.M) {
	pathstest.Main(m)
}

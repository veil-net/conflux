// Package pathstest roots conflux in a directory of a test's own, and is only for tests.
//
// It is apart from anchortest, which imports anchor, so that a package's tests can root
// conflux without the anchor pair embedded in their binary.
package pathstest

import (
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// Main is a package's TestMain: it roots every conflux path in a directory of the run's own
// before any test starts, runs them, and removes it, so a test that does not root its own
// reaches nothing of the machine's .conflux.
func Main(m *testing.M) {
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

// Root roots every conflux path in a directory of the test's own, made as EnsureAll makes
// the machine's, and puts the root back when the test ends.
func Root(tb testing.TB) paths.Dirs {
	tb.Helper()
	tb.Cleanup(paths.UseRoot(tb.TempDir()))

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		tb.Fatalf("EnsureAll: %v", err)
	}

	return d
}

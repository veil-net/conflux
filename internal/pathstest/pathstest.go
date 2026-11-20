// Package pathstest is for tests that need conflux's directories, and only for tests.
//
// It imports paths alone, so any package's tests can use it, config's and libexec's among them.
package pathstest

import (
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// Dirs roots every conflux path in a fresh temporary directory, as CONFLUX_DIR roots a dev
// run, for the rest of the test, and makes the directories.
func Dirs(tb testing.TB) paths.Dirs {
	tb.Helper()
	tb.Setenv("CONFLUX_DIR", tb.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		tb.Fatalf("EnsureAll: %v", err)
	}

	return d
}

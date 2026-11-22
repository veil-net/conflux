// Package pathstest is for tests that need conflux's directories, and only for tests.
//
// It imports paths alone, and on Windows privtest, which imports nothing of conflux's, so any
// package's tests can use it, config's and libexec's among them. On Windows every test linking it
// makes what it makes the Administrators', as conflux does, and roots it on a way the boot service
// trusts (pathstest_windows.go).
package pathstest

import (
	"os"
	"runtime"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// Dirs roots every conflux path in a fresh temporary directory, as CONFLUX_DIR roots a dev
// run, for the rest of the test, and makes the directories.
func Dirs(tb testing.TB) paths.Dirs {
	tb.Helper()

	return DirsIn(tb, tb.TempDir())
}

// DirsIn is Dirs rooted in root.
func DirsIn(tb testing.TB, root string) paths.Dirs {
	tb.Helper()
	tb.Setenv("CONFLUX_DIR", root)

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		tb.Fatalf("EnsureAll: %v", err)
	}

	return d
}

// Temporary makes dir the process's temporary directory for the rest of the test -- TMPDIR, and TMP and
// TEMP, which on Windows a test linking this package keeps %ProgramData%'s in too -- and is dir: where a
// reader's temporary anchorctl is made, whether conflux runs elevated or not, so that what a test makes
// there is rooted in a directory of its own.
func Temporary(tb testing.TB, dir string) string {
	tb.Helper()

	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		tb.Setenv(name, dir)
	}

	return dir
}

// ShortRoot is a fresh directory with a short name, removed when the test ends, for a root a
// control socket lies below: TempDir's is named after the test, and a unix socket's path has
// room for 103 bytes on macOS and 107 on Linux and Windows. A test named at length under
// Windows's %TEMP% would otherwise pass that, and be refused for it. macOS's $TMPDIR is long
// enough by itself, so there it is /tmp.
func ShortRoot(tb testing.TB) string {
	tb.Helper()

	base := ""
	if runtime.GOOS == "darwin" {
		base = "/tmp"
	}

	root, err := os.MkdirTemp(base, "cfx")
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() { _ = os.RemoveAll(root) })

	return root
}

// Package pathstest is for tests that need conflux's directories, and only for tests.
//
// It imports paths alone, and on Windows privtest, which imports nothing of conflux's, so any
// package's tests can use it, config's and libexec's among them. On Windows every test linking it
// makes what it makes the Administrators', as conflux does, and roots it on a way the boot service
// trusts (pathstest_windows.go).
package pathstest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// Dirs roots every conflux path in a fresh temporary directory, for the rest of the test, and makes the
// directories.
func Dirs(tb testing.TB) paths.Dirs {
	tb.Helper()

	return DirsIn(tb, tb.TempDir())
}

// DirsIn is Dirs rooted in root (RootedIn).
func DirsIn(tb testing.TB, root string) paths.Dirs {
	tb.Helper()

	d := RootedIn(tb, root)
	if err := d.EnsureAll(); err != nil {
		tb.Fatalf("EnsureAll: %v", err)
	}

	return d
}

// RootedIn roots every conflux path in dir for the rest of the test, and makes nothing: the installation's
// root, DirName, kept in dir as the system's data folder (paths.SystemData), and an ephemeral run's in a
// runtime folder of its own (Runtime), so that nothing the test runs reaches the system's. It is the
// installation's Dirs.
func RootedIn(tb testing.TB, dir string) paths.Dirs {
	tb.Helper()

	was := paths.SystemData
	paths.SystemData = func() string { return dir }

	tb.Cleanup(func() { paths.SystemData = was })
	Runtime(tb, tb.TempDir())

	return paths.Default()
}

// Runtime keeps an ephemeral run's root in dir, as the runtime folder (paths.RuntimeFolder), for the rest
// of the test, and is dir.
func Runtime(tb testing.TB, dir string) string {
	tb.Helper()

	was := paths.RuntimeFolder
	paths.RuntimeFolder = func() (string, error) { return dir, nil }

	tb.Cleanup(func() { paths.RuntimeFolder = was })

	return dir
}

// Temporary roots, for the rest of the test, every place a reader's temporary anchorctl may be made in
// dir (temporaryIn), and is dir: so that what a test makes there, and what an uninstall or a tidy it runs
// removes there, is in a directory of its own.
func Temporary(tb testing.TB, dir string) string {
	tb.Helper()

	temporaryIn(dir, tb.Setenv)

	return dir
}

// SetTemporary roots every place a reader's temporary anchorctl may be made in dir (temporaryIn) for the
// rest of the process: for a package's TestMain.
func SetTemporary(dir string) error {
	var err error

	temporaryIn(dir, func(name, value string) {
		if e := os.Setenv(name, value); e != nil {
			err = e
		}
	})

	return err
}

// temporaryIn sets, through set, every variable that says where a reader's temporary anchorctl may be
// made: the temporary directory, dir -- TMPDIR, and TMP and TEMP, which on Windows a test linking this
// package keeps %ProgramData%'s in too, where an elevated reader makes it -- and on Unix the user's cache
// directory, where one goes on a host whose temporary directory is mounted noexec, in dir as well:
// XDG_CACHE_HOME, or macOS's HOME, beneath which it is Library/Caches.
func temporaryIn(dir string, set func(name, value string)) {
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		set(name, dir)
	}

	switch runtime.GOOS {
	case "windows": // no cache directory: Windows mounts nothing noexec
	case "darwin":
		set("HOME", filepath.Join(dir, "home"))
	default:
		set("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	}
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

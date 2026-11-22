//go:build !windows

package pathstest

import (
	"os"
	"testing"
)

// ProgramData is "": there is no %ProgramData% but on Windows (pathstest_windows.go).
func ProgramData(testing.TB, string) string { return "" }

// NotAsConfluxMakesIt makes p, a root of conflux's, or a file or a folder in one, one every account may
// write: not as conflux makes one of its own.
func NotAsConfluxMakesIt(tb testing.TB, p string) {
	tb.Helper()

	if err := os.Chmod(p, 0o757); err != nil {
		tb.Fatal(err)
	}
}

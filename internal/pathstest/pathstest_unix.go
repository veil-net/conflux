//go:build !windows

package pathstest

import (
	"os"
	"testing"
)

// NotAsConfluxMakesIt makes p, a root of conflux's, or a file or a folder in one, one every account may
// write: not as conflux makes one of its own.
func NotAsConfluxMakesIt(tb testing.TB, p string) {
	tb.Helper()

	if err := os.Chmod(p, 0o757); err != nil {
		tb.Fatal(err)
	}
}

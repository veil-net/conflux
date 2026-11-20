// Package anchortest is for tests that need the real anchor pair, and only for tests.
package anchortest

import (
	"runtime"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

// Require skips the test when this build carries no anchor pair.
//
// One message for every such skip, because CI keys on it: the jobs that fetch the pair
// fail a run in which any test skipped saying "no anchor pair", since there the pair was
// fetched and then lost.
func Require(tb testing.TB) {
	tb.Helper()

	if !anchor.Supported {
		tb.Skipf("no anchor pair for %s/%s -- run `make anchor-bins`", runtime.GOOS, runtime.GOARCH)
	}
}

// Extracted is the pair, extracted for a test that runs it: skipped by Require where this build
// carries none, and otherwise extracted by extract into a fresh CONFLUX_DIR (pathstest.Dirs).
// extract is libexec.Ensure, passed in because libexec's own tests import this package.
func Extracted[T any](tb testing.TB, extract func(paths.Dirs) (T, error)) T {
	tb.Helper()

	Require(tb)

	tools, err := extract(pathstest.Dirs(tb))
	if err != nil {
		tb.Fatalf("Ensure: %v", err)
	}

	return tools
}

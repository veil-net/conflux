// Package anchortest is for tests that need the real anchor pair, and only for tests.
package anchortest

import (
	"runtime"
	"testing"

	"github.com/veil-net/conflux/anchor"
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

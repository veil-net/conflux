// Package goldentest is for tests that hold an output to a committed golden file, and only for
// tests.
//
// Every package whose tests import it gets the -update flag, and `make golden` runs exactly
// those packages with it, so a golden file is rewritten by the same flag wherever it lives.
package goldentest

import (
	"bytes"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files, and any fixture a test makes for them (make golden)")

// Updating reports whether this run rewrites the golden files rather than comparing them.
func Updating() bool { return *update }

// Check holds got to the golden file at path, or under -update writes it there.
func Check(tb testing.TB, path string, got []byte) {
	tb.Helper()

	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			tb.Fatalf("write golden: %v", err)
		}

		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read golden (make golden writes it): %v", err)
	}

	if !bytes.Equal(got, want) {
		tb.Errorf("%s changed.\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

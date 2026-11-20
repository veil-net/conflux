//go:build unix

package logfile

import (
	"testing"

	"golang.org/x/sys/unix"
)

// keepStandardStreams copies stdout and stderr aside and returns what puts them back.
func keepStandardStreams(t *testing.T) func() {
	t.Helper()

	out, err := unix.Dup(1)
	if err != nil {
		t.Fatal(err)
	}

	errs, err := unix.Dup(2)
	if err != nil {
		t.Fatal(err)
	}

	return func() {
		_ = unix.Dup2(out, 1)
		_ = unix.Dup2(errs, 2)
		_ = unix.Close(out)
		_ = unix.Close(errs)
	}
}

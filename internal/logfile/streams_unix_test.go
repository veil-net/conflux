//go:build unix

package logfile

import (
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// keepStandardStreams copies stdout and stderr aside and returns what puts them back, which the
// test's cleanup calls too: a test puts them back before it checks what it found, so that what
// it says reaches the terminal rather than the log.
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

	restore := sync.OnceFunc(func() {
		_ = unix.Dup2(out, 1)
		_ = unix.Dup2(errs, 2)
		_ = unix.Close(out)
		_ = unix.Close(errs)
	})

	t.Cleanup(restore)

	return restore
}

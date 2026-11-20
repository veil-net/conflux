package logfile

import (
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// keepStandardStreams notes the standard handles and returns what puts them back, which the
// test's cleanup calls too: a test puts them back before it checks what it found, so that what
// it says reaches the terminal rather than the log. The log's copy goes with them, so that the
// test's directory can be removed.
func keepStandardStreams(t *testing.T) func() {
	t.Helper()

	out, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		t.Fatal(err)
	}

	errs, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	if err != nil {
		t.Fatal(err)
	}

	restore := sync.OnceFunc(func() {
		unplace()

		_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, out)
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, errs)
	})

	t.Cleanup(restore)

	return restore
}

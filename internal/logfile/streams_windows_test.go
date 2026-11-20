package logfile

import (
	"testing"

	"golang.org/x/sys/windows"
)

// keepStandardStreams notes the standard handles and returns what puts them back.
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

	return func() {
		_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, out)
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, errs)
	}
}

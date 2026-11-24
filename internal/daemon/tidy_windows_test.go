package daemon

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/paths"
)

// widen grants Users read access to path, as somebody might since.
func widen(t *testing.T, path string) {
	t.Helper()

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}

	if err := grantSID(path, users, windows.FILE_GENERIC_READ); err != nil {
		t.Fatal(err)
	}

	if paths.OnlyAdmins(path) {
		t.Fatalf("%s, granted to Users, reads as SYSTEM's and the Administrators' alone", path)
	}
}

// restored reports whether path is SYSTEM's and the Administrators' alone again, whatever mode
// it has on Unix.
func restored(path string, _ os.FileMode) bool { return paths.OnlyAdmins(path) }

// stuck holds the file at path open, without share-delete, for the rest of the test: Windows
// removes no file held so.
func stuck(t *testing.T, path string) {
	t.Helper()

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = windows.CloseHandle(h) })
}

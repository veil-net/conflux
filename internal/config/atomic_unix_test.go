//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteFileIfChangedTakesBackAnotherAccountsFile: a file holding what conflux writes, at its
// mode, that another account owns -- and so can make writable, or write, whenever it likes --
// is written again, a file of conflux's own, rather than left as it is.
func TestWriteFileIfChangedTakesBackAnotherAccountsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux.service")

	if _, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}

	other := os.Geteuid() + 1
	if err := os.Chown(path, other, -1); err != nil {
		t.Skipf("giving a file to another account needs root: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if wrote, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil || !wrote {
		t.Errorf("WriteFileIfChanged over the same bytes, owned by uid %d = %v, %v; want it written", other, wrote, err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if uid := after.Sys().(*syscall.Stat_t).Uid; int(uid) != os.Geteuid() || os.SameFile(before, after) {
		t.Errorf("after the start the file is uid %d's, the same file %v; want a new file, uid %d's",
			uid, os.SameFile(before, after), os.Geteuid())
	}

	if got := after.Mode().Perm(); got != 0o644 {
		t.Errorf("the file written again is %o, want 644", got)
	}
}

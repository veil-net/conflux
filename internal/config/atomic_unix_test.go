//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileIfChangedTakesBackAnotherAccountsFile: a file holding what conflux writes, at its
// mode, that another account owns -- and so can make writable, or write, whenever it likes --
// is written again, a new file of the writer's own, rather than left as it is. Another account
// is the writer seen as somebody else (euid), so this runs as root or not, as the gates need.
func TestWriteFileIfChangedTakesBackAnotherAccountsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux.service")

	if _, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if wrote, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil || wrote {
		t.Fatalf("WriteFileIfChanged over its own file's same bytes = %v, %v; want it kept", wrote, err)
	}

	was := euid
	euid = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { euid = was })

	if wrote, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil || !wrote {
		t.Errorf("WriteFileIfChanged over the same bytes another account owns = %v, %v; want it written", wrote, err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if os.SameFile(before, after) {
		t.Error("another account's file was kept, not written again as a new file")
	}

	if got := after.Mode().Perm(); got != 0o644 {
		t.Errorf("the file written again is %o, want 644", got)
	}
}

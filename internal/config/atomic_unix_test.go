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

// TestWriteFileIfChangedLeavesTheSameBytesAlone: a start puts conflux's files back to what
// conflux writes, and a file that already holds that is not written -- not renamed over, so
// it keeps its inode and its mtime -- while one that differs is replaced.
func TestWriteFileIfChangedLeavesTheSameBytesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux")

	if wrote, err := WriteFileIfChanged(path, []byte("one"), 0o600); err != nil || !wrote {
		t.Fatalf("WriteFileIfChanged of a missing file = %v, %v; want it written", wrote, err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if wrote, err := WriteFileIfChanged(path, []byte("one"), 0o600); err != nil || wrote {
		t.Fatalf("WriteFileIfChanged of the same bytes = %v, %v; want nothing written", wrote, err)
	}

	same, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(before, same) || !same.ModTime().Equal(before.ModTime()) {
		t.Error("the same bytes were written again: the file is not the one that was there")
	}

	if wrote, err := WriteFileIfChanged(path, []byte("two"), 0o600); err != nil || !wrote {
		t.Fatalf("WriteFileIfChanged of other bytes = %v, %v; want them written", wrote, err)
	}

	if b, err := os.ReadFile(path); err != nil || string(b) != "two" {
		t.Errorf("the file holds %q (%v), want %q", b, err, "two")
	}
}

// TestWriteFileIfChangedPutsTheModeBack: a file that holds what conflux writes but was made
// group- or world-writable since -- a registration, which the service manager runs what it
// names from -- is given its mode back where it is, keeping its inode and its mtime, and
// reported as not written.
func TestWriteFileIfChangedPutsTheModeBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conflux.service")

	if _, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, widened := range []os.FileMode{0o664, 0o666, 0o646} {
		if err := os.Chmod(path, widened); err != nil {
			t.Fatal(err)
		}

		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if wrote, err := WriteFileIfChanged(path, []byte("unit"), 0o644); err != nil || wrote {
			t.Errorf("WriteFileIfChanged over a %o file of the same bytes = %v, %v; want its mode put back, not written",
				widened, wrote, err)
		}

		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if got := after.Mode().Perm(); got != 0o644 {
			t.Errorf("a file made %o is %o after a start, want 644", widened, got)
		}

		if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("a file made %o was written again rather than given its mode back", widened)
		}
	}
}

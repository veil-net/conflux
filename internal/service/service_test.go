package service

import (
	"bytes"
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// TestPlaceCopiesWhatTheServiceRuns: the boot service runs a copy in the state
// directory, which only root can write, and not wherever conflux was run from. The copy
// is this executable byte for byte, left alone while it still is, and replaced when it
// is not -- an upgraded conflux reaches the service at its next install.
func TestPlaceCopiesWhatTheServiceRuns(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	src, err := executable()
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	placed, err := Place(d)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}

	if placed != d.ServiceExecutable() {
		t.Errorf("placed at %s, want %s", placed, d.ServiceExecutable())
	}

	got, err := os.ReadFile(placed)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the placed copy is not this executable (%v)", err)
	}

	before, _ := os.Stat(placed)

	if _, err := Place(d); err != nil {
		t.Fatalf("Place again: %v", err)
	}

	if after, _ := os.Stat(placed); !os.SameFile(before, after) {
		t.Error("an identical copy was written again")
	}

	// A copy that is no longer this conflux -- an older one, or one somebody changed --
	// is replaced.
	if err := os.WriteFile(placed, []byte("an older conflux"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := Place(d); err != nil {
		t.Fatalf("Place over a stale copy: %v", err)
	}

	if got, _ := os.ReadFile(placed); !bytes.Equal(got, want) {
		t.Error("a stale copy was left in place")
	}

	if info, _ := os.Stat(placed); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the placed copy is %v, want it closed to everybody but its owner", info.Mode().Perm())
	}
}

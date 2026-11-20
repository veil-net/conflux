package service

import (
	"bytes"
	"os"
	"testing"

	"github.com/veil-net/conflux/internal/pathstest"
)

// TestPlaceCopiesWhatTheServiceRuns: the boot service runs a copy in the state
// directory, which only root can write, and not wherever conflux was run from. The copy
// is this executable byte for byte, left alone while it still is, and replaced when it
// is not -- an upgraded conflux reaches the service at its next install.
func TestPlaceCopiesWhatTheServiceRuns(t *testing.T) {
	d := pathstest.Dirs(t)

	src, err := Executable()
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

	// A copy that is no longer this conflux is replaced: an older one, and one somebody
	// changed, which is the same size -- a byte changed at its end, past the first buffer
	// compared.
	changed := bytes.Clone(want)
	changed[len(changed)-1] ^= 0xff

	for name, stale := range map[string][]byte{"an older conflux": []byte("an older conflux"), "one somebody changed": changed} {
		if err := os.WriteFile(placed, stale, 0o700); err != nil {
			t.Fatal(err)
		}

		if _, err := Place(d); err != nil {
			t.Fatalf("Place over %s: %v", name, err)
		}

		if got, _ := os.ReadFile(placed); !bytes.Equal(got, want) {
			t.Errorf("%s was left in place", name)
		}
	}

	if info, _ := os.Stat(placed); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the placed copy is %v, want it closed to everybody but its owner", info.Mode().Perm())
	}
}

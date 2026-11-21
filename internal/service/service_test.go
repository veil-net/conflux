package service

import (
	"bytes"
	"os"
	"testing"

	_ "github.com/veil-net/conflux/internal/apitest" // the default API answers nothing
	"github.com/veil-net/conflux/internal/pathstest"
)

// TestPlaceAfreshCopiesWhatTheServiceRuns: the boot service runs a copy in the state directory,
// which only root can write, and not wherever conflux was run from. PlaceAfresh writes it, this
// executable byte for byte, which Placed then finds it is, and Keep leaves alone; and a copy that is no
// longer this conflux, Placed finds is not, and PlaceAfresh replaces -- an upgraded conflux reaches the
// service at its next install. PlaceAfresh writes even a copy that is this conflux again, a new file, so
// that no handle on the one before outlives it.
func TestPlaceAfreshCopiesWhatTheServiceRuns(t *testing.T) {
	d := pathstest.Dirs(t)

	src, err := Executable()
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	placed, err := PlaceAfresh(d)
	if err != nil {
		t.Fatalf("PlaceAfresh: %v", err)
	}

	if placed != d.ServiceExecutable() {
		t.Errorf("placed at %s, want %s", placed, d.ServiceExecutable())
	}

	got, err := os.ReadFile(placed)
	if err != nil || !bytes.Equal(got, want) || !Placed(d) {
		t.Fatalf("the placed copy is not this executable (Placed: %v, %v)", Placed(d), err)
	}

	before, _ := os.Stat(placed)

	if kept := Keep(d); kept != placed {
		t.Errorf("Keep = %s, want %s", kept, placed)
	}

	if after, _ := os.Stat(placed); !os.SameFile(before, after) {
		t.Error("Keep wrote the copy again")
	}

	if _, err := PlaceAfresh(d); err != nil {
		t.Fatalf("PlaceAfresh over this conflux: %v", err)
	}

	if after, _ := os.Stat(placed); os.SameFile(before, after) {
		t.Error("PlaceAfresh kept a copy that is this conflux, rather than writing it afresh")
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

		if Placed(d) {
			t.Errorf("Placed took %s for this conflux", name)
		}

		if _, err := PlaceAfresh(d); err != nil {
			t.Fatalf("PlaceAfresh over %s: %v", name, err)
		}

		if got, _ := os.ReadFile(placed); !bytes.Equal(got, want) {
			t.Errorf("%s was left in place", name)
		}
	}

	if info, _ := os.Stat(placed); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the placed copy is %v, want it closed to everybody but its owner", info.Mode().Perm())
	}
}

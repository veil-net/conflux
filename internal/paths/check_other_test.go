//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckHoldsARootAsConfluxMakesOne: Check holds each root that is there to what conflux makes a root
// as, changing nothing: a root of this account's at 0700, or at 0750, which it leaves at 0750, passes;
// one every account may write, sticky or not, is refused, naming it, and so is a link at its name, even
// to a directory of this account's own. A CONFLUX_DIR inside a directory every account may write is
// refused for it. Where no root is there Check is fs.ErrNotExist, and where one of several is there, nil.
func TestCheckHoldsARootAsConfluxMakesOne(t *testing.T) {
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	root := d.State

	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o700, true}, {0o750, true}, {0o757, false}, {0o777 | os.ModeSticky, false}} {
		if err := os.Chmod(root, c.mode); err != nil {
			t.Fatal(err)
		}

		switch err := d.Check(); {
		case c.ok && err != nil:
			t.Errorf("Check(a root at %v) = %v", c.mode, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes")):
			t.Errorf("Check(a root at %v) = %v, want a refusal naming it", c.mode, err)
		}

		if fi, err := os.Stat(root); err != nil || fi.Mode()&(os.ModePerm|os.ModeSticky) != c.mode {
			t.Errorf("Check changed %s from %v: %v, %v", root, c.mode, fi.Mode(), err)
		}
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes") {
		t.Errorf("Check(a link at the root's name) = %v, want a refusal naming it", err)
	}

	parent := realTempDir(t)
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	if err := os.MkdirAll(Default().State, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Default().Check(); err == nil || !strings.Contains(err.Error(), "inside "+parent) {
		t.Errorf("Check(a CONFLUX_DIR in a directory every account may write) = %v, want a refusal naming it", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	mine := foundRoot(t)
	absent := filepath.Join(t.TempDir(), "absent")

	if err := (Dirs{Config: absent, State: absent, Run: filepath.Join(absent, "run")}).Check(); !errors.Is(err,
		fs.ErrNotExist) {
		t.Errorf("Check(no root there) = %v, want %v", err, fs.ErrNotExist)
	}

	if err := (Dirs{Config: mine, State: absent, Run: filepath.Join(t.TempDir(), "run")}).Check(); err != nil {
		t.Errorf("Check(one root of three there) = %v", err)
	}
}

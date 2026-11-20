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

// TestCheckHoldsARootAsAReaderNeeds: Check holds each root that is there to its owner -- root or
// this account -- and to who else may write it, as found and changing nothing: a root of this
// account's at 0700, or at 0750, which it leaves at 0750, passes, as does a directory root owns; one
// every account may write, sticky or not, is refused, naming it, and so is one another uid owns,
// and a link to one every account may write, named as the link. A CONFLUX_DIR inside a directory
// every account may write is refused for it. Where no root is there Check is fs.ErrNotExist, and
// where one of several is there, nil.
func TestCheckHoldsARootAsAReaderNeeds(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	euid := os.Geteuid()

	mine := foundRoot(t)
	if err := os.Chmod(mine, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{mine, "/"} {
		if err := checkRootAs(dir, euid); err != nil {
			t.Errorf("checkRootAs(%s) = %v", dir, err)
		}
	}

	if fi, err := os.Stat(mine); err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("Check changed %s: %v, %v", mine, fi.Mode(), err)
	}

	if err := checkRootAs(mine, euid+1); err == nil || !strings.Contains(err.Error(), mine+" belongs to uid") {
		t.Errorf("checkRootAs(a root another uid owns) = %v, want a refusal naming it", err)
	}

	for _, mode := range []os.FileMode{0o757, 0o1777} {
		open := foundRoot(t)
		if err := os.Chmod(open, mode); err != nil {
			t.Fatal(err)
		}

		if err := checkRootAs(open, euid); err == nil || !strings.Contains(err.Error(), open+" is not conflux's alone") {
			t.Errorf("checkRootAs(a root at %v) = %v, want a refusal naming it", mode, err)
		}

		link := filepath.Join(t.TempDir(), "conflux")
		if err := os.Symlink(open, link); err != nil {
			t.Fatal(err)
		}

		if err := checkRootAs(link, euid); err == nil || !strings.Contains(err.Error(), link+" is not conflux's alone") {
			t.Errorf("checkRootAs(a link to a root at %v) = %v, want a refusal naming it", mode, err)
		}
	}

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	if err := os.Mkdir(Root(), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Default().Check(); err == nil || !strings.Contains(err.Error(), "inside "+parent) {
		t.Errorf("Check(a CONFLUX_DIR in a directory every account may write) = %v, want a refusal naming it", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	absent := filepath.Join(t.TempDir(), "absent")
	if err := (Dirs{Config: absent, State: absent, Run: filepath.Join(absent, "run")}).Check(); !errors.Is(err,
		fs.ErrNotExist) {
		t.Errorf("Check(no root there) = %v, want %v", err, fs.ErrNotExist)
	}

	if err := (Dirs{Config: mine, State: absent, Run: filepath.Join(t.TempDir(), "run")}).Check(); err != nil {
		t.Errorf("Check(one root of three there) = %v", err)
	}
}

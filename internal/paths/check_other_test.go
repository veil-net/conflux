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
// to a directory of this account's own. A root in a directory every account may write passes: nothing
// above a root is judged. Where no root is there Check is fs.ErrNotExist.
func TestCheckHoldsARootAsConfluxMakesOne(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	root := d.Root

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

	inData(t, parent)

	if err := os.MkdirAll(Default().Root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a root in a directory every account may write) = %v", err)
	}

	if err := (Dirs{Root: filepath.Join(t.TempDir(), "absent")}).Check(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Check(no root there) = %v, want %v", err, fs.ErrNotExist)
	}
}

// TestEnsureAllRemovesAFileNotAsConfluxMakesIt: each file conflux keeps in a root -- the configuration,
// the state, the identity, the record of the anchord last started, the lock files, the copy the boot
// service runs -- is judged as a folder of
// conflux's is (ours), and one that is not as conflux makes it -- a link, a folder, a file every account
// may write -- is removed as itself, where a link leads untouched, and nothing made in its place; one as
// conflux makes it is kept, and anchord's own configuration, which the account anchord runs as owns, is
// not judged. EnsureServing, the supervisor's, which runs from the copy the boot service names, leaves
// that copy alone and removes the rest alike. Ours holds a file to the same, the copy among them, and one in a folder conflux keeps in a
// root, each folder on the way to it held too: nil for one as conflux makes it, fs.ErrNotExist for one
// not there, and otherwise a refusal saying why; and OursFolder a folder, the bin directory.
func TestEnsureAllRemovesAFileNotAsConfluxMakesIt(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	file := func(p string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte("planted"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}

	for p, plant := range map[string]func(string){
		d.ConfigFile():        func(p string) { _ = os.Symlink(elsewhere, p) },
		d.StateFile():         func(p string) { _ = os.Mkdir(p, 0o700) },
		d.ManifestFile():      func(p string) { file(p, 0o606) },
		d.PrivilegeFile():     func(p string) { file(p, 0o646) },
		d.LockFile():          func(p string) { file(p, 0o602) },
		d.ServiceExecutable(): func(p string) { file(p, 0o757) },
	} {
		plant(p)
	}

	for _, p := range []string{d.ServeLockFile(), d.DaemonConfigFile()} {
		file(p, 0o600)
	}

	if err := os.Chmod(d.DaemonConfigFile(), 0o606); err != nil {
		t.Fatal(err)
	}

	if err := d.Ours(d.ServiceExecutable()); err == nil || !strings.Contains(err.Error(), "anybody may write") {
		t.Errorf("Ours(a copy every account may write) = %v, want a refusal saying so", err)
	}

	if err := d.EnsureServing(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(d.ServiceExecutable()); err != nil {
		t.Errorf("EnsureServing removed the copy the supervisor runs from: %v", err)
	}

	if _, err := os.Lstat(d.ManifestFile()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureServing left %s, which is not as conflux makes it (Lstat: %v)", d.ManifestFile(), err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.LockFile(),
		d.ServiceExecutable()} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("EnsureAll left %s, which is not as conflux makes it (Lstat: %v)", p, err)
		}
	}

	for _, p := range []string{d.ServeLockFile(), d.DaemonConfigFile(), elsewhere} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("EnsureAll removed %s: %v", p, err)
		}
	}

	if err := d.Ours(d.ServiceExecutable()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Ours(no copy there) = %v, want %v", err, fs.ErrNotExist)
	}

	file(d.ServiceExecutable(), 0o700)

	if err := d.Ours(d.ServiceExecutable()); err != nil {
		t.Errorf("Ours(a copy as conflux makes it) = %v", err)
	}

	set := filepath.Join(d.Libexec(), "set")
	if err := os.MkdirAll(set, 0o700); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(set, "anchorctl")
	file(bin, 0o700)

	if err := d.Ours(bin); err != nil {
		t.Errorf("Ours(%s, as conflux makes it) = %v", bin, err)
	}

	if err := os.Chmod(set, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := d.Ours(bin); err == nil || !strings.Contains(err.Error(), set+" is not as conflux makes it") {
		t.Errorf("Ours(%s, in a folder every account may write) = %v, want a refusal naming the folder", bin, err)
	}

	if err := os.RemoveAll(set); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(t.TempDir(), set); err != nil {
		t.Fatal(err)
	}

	if err := d.Ours(bin); err == nil || !strings.Contains(err.Error(), "a link") {
		t.Errorf("Ours(%s, through a link) = %v, want a refusal saying so", bin, err)
	}

	// OursFolder holds a folder to the same: the bin directory a reader extracts into.
	if err := d.OursFolder(d.Libexec()); err != nil {
		t.Errorf("OursFolder(%s, as conflux makes it) = %v", d.Libexec(), err)
	}

	if err := d.Ours(d.Libexec()); err == nil || !strings.Contains(err.Error(), "not a file") {
		t.Errorf("Ours(%s, a folder) = %v, want a refusal saying it is no file", d.Libexec(), err)
	}

	if err := os.Chmod(d.Libexec(), 0o777); err != nil {
		t.Fatal(err)
	}

	if err := d.OursFolder(d.Libexec()); err == nil || !strings.Contains(err.Error(), "anybody may write") {
		t.Errorf("OursFolder(%s, every account may write it) = %v, want a refusal saying so", d.Libexec(), err)
	}

	if err := os.RemoveAll(d.Libexec()); err != nil {
		t.Fatal(err)
	}

	if err := d.OursFolder(d.Libexec()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OursFolder(no folder there) = %v, want %v", err, fs.ErrNotExist)
	}

	if err := os.Symlink(t.TempDir(), d.Libexec()); err != nil {
		t.Fatal(err)
	}

	if err := d.OursFolder(d.Libexec()); err == nil || !strings.Contains(err.Error(), "a link") {
		t.Errorf("OursFolder(a link) = %v, want a refusal saying so", err)
	}

	if err := os.Remove(d.Libexec()); err != nil {
		t.Fatal(err)
	}

	file(d.Libexec(), 0o700)

	if err := d.OursFolder(d.Libexec()); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("OursFolder(a file) = %v, want a refusal saying it is no folder", err)
	}
}

// TestARootItsGroupMayWriteIsRemade: a root, or a folder or a file conflux keeps in one, that its group
// may write -- by its mode or by an ACL entry for a group -- is not as conflux makes it, whatever the group
// is, a group of this account alone among them: the readers' check refuses it, naming the group, and
// EnsureAll removes it as itself and makes it afresh. Here the group is this account's own.
func TestARootItsGroupMayWriteIsRemade(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	planted := filepath.Join(d.Root, "planted")
	if err := os.WriteFile(planted, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(d.Root, 0o770); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil || !strings.Contains(err.Error(), d.Root+" is not as conflux makes") ||
		!strings.Contains(err.Error(), "its group") {
		t.Errorf("Check(a root its group may write) = %v, want a refusal naming it and its group", err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, d.Root); got != 0o700 {
		t.Errorf("EnsureAll left the root %v, want it made afresh at 0700", got)
	}

	if _, err := os.Lstat(planted); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the root made afresh holds what the one its group could write held (Lstat: %v)", err)
	}

	if err := os.WriteFile(d.ManifestFile(), nil, 0o660); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(d.ManifestFile(), 0o660); err != nil {
		t.Fatal(err)
	}

	if err := d.Ours(d.ManifestFile()); err == nil || !strings.Contains(err.Error(), "its group") {
		t.Errorf("Ours(a manifest its group may write) = %v, want a refusal naming its group", err)
	}
}

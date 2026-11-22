//go:build !windows

package paths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the directory the walk to it holds,
// following nothing: a link in it to a directory outside, and one deeper, are removed as links, with
// what each led to untouched, and so is a link at the root's own name. A root found 0757, which the
// readers' check refuses, is removed all the same, and the folder it is in is left. A root not there is
// nothing removed.
func TestRemoveRootFollowsNothing(t *testing.T) {
	dir := t.TempDir()
	inData(t, dir)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	root := d.Root

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, link := range []string{d.ConfigFile(), filepath.Join(d.RunDir(), "anchord")} {
		if err := os.Symlink(elsewhere, link); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil {
		t.Fatalf("Check(a root at 0757) = nil, want the readers' refusal this is about")
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	if _, err := os.Lstat(dir); err != nil {
		t.Errorf("RemoveRoot removed the folder %s its root was in: %v", dir, err)
	}

	if err := os.Symlink(elsewhere, root); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s, a link) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link %s is there once RemoveRoot removed it (%v)", root, err)
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
		t.Errorf("RemoveRoot reached %s through a link: %q, %v", kept, b, err)
	}

	for _, absent := range []string{root, filepath.Join(t.TempDir(), "not", "there")} {
		if gone, err := RemoveRoot(absent); gone || err != nil {
			t.Errorf("RemoveRoot(%s, which is not there) = %v, %v, want nothing removed", absent, gone, err)
		}
	}
}

// TestRemoveRootJudgesNoFolderAboveIt: nothing above a root is judged before it is removed, as nothing is
// when it is made: with a directory every account may write above it, RemoveRoot removes the root.
func TestRemoveRootJudgesNoFolderAboveIt(t *testing.T) {
	open := realTempDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	inData(t, made(t, filepath.Join(open, "a")))

	root := Default().Root
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a root inside a directory anybody may write) = %v, %v, want it removed", gone, err)
	}
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root by a command that has not made it --
// the serve lock tidy asks after -- is opened through the root held (OpenIn), never by its name, and only
// where what is at the root's name is as conflux makes a root (ours): a directory of this account's own at
// 0700 is read, and a link at the name -- to a directory of this account's own, the directory it is in, or
// nothing -- is none of conflux's, and taken as no root at all, nothing in it opened; and so is a
// directory of this account's own every account may write.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base := realTempDir(t)

	inData(t, base)

	d := Default()
	root := d.Root

	plant := func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "serve.lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range []struct {
		name string
		make func(t *testing.T)
		ok   bool
	}{
		{"a directory of this account's own", func(t *testing.T) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			plant(root)
		}, true},
		{"a directory of this account's own every account may write", func(t *testing.T) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			plant(root)

			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a link to a directory of this account's own", func(t *testing.T) {
			if err := os.Symlink(mine(t, 0o700, plant), root); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a link to the directory it is in", func(t *testing.T) {
			plant(base)

			if err := os.Symlink(base, root); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a link to nothing", func(t *testing.T) {
			if err := os.Symlink(filepath.Join(base, "missing"), root); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.make(t)
			t.Cleanup(func() { os.RemoveAll(root) })

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			switch {
			case c.ok && err != nil:
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want it opened", c.name, err)
			case !c.ok && !errors.Is(err, fs.ErrNotExist):
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want none of conflux's", c.name, err)
			}

			switch err := d.Check(); {
			case c.ok && err != nil:
				t.Errorf("Check(), the root %s = %v, want it taken", c.name, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes")):
				t.Errorf("Check(), the root %s = %v, want a refusal naming it", c.name, err)
			}
		})
	}
}

// TestOursHoldsARootToItsOwnerAndWriters: a directory at a root's name is as conflux makes one where root
// or this account owns it and nobody else may write it, by its mode as fstat read it where the walk met
// it: 0700, the 0710 the supervisor gives the state and run directories, and 0755 are; 0777, 01777 and
// another account's are not -- judged here from a constructed step, an owner of this test's making, so
// on every machine and as every account.
func TestOursHoldsARootToItsOwnerAndWriters(t *testing.T) {
	dir := t.TempDir()
	me := uint32(os.Geteuid())

	for _, c := range []struct {
		uid  uint32
		mode uint32
		ok   bool
	}{
		{me, 0o700, true}, {me, 0o710, true}, {me, 0o755, true}, {0, 0o700, true},
		{me, 0o777, false}, {me, 0o1777, false}, {me + 1, 0o700, me+1 == 0},
	} {
		s := step{st: unix.Stat_t{Uid: c.uid}}
		reflect.ValueOf(&s.st.Mode).Elem().SetUint(uint64(unix.S_IFDIR | c.mode)) // uint16 on macOS and the BSDs

		why, err := ours(dir, s)
		if err != nil || (why == "") != c.ok {
			t.Errorf("ours(uid %d, %#o) = %q, %v, want it ours: %v", c.uid, c.mode, why, err, c.ok)
		}
	}
}

// mine is a directory of this account's own at mode, with plant called on it first.
func mine(t *testing.T, mode os.FileMode, plant func(dir string)) string {
	t.Helper()

	dir := t.TempDir()
	plant(dir)

	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestOpenInReadsThroughTheRootHeld: what OpenIn opens is looked up in the root it holds, and not by its
// name, so a root put at the name once OpenIn holds the one there -- the one held moved aside, another
// made in its place holding a lock of its own -- answers for nothing: what is read is the held root's.
func TestOpenInReadsThroughTheRootHeld(t *testing.T) {
	inData(t, t.TempDir())

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.ServeLockFile(), []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}

	was := opening
	t.Cleanup(func() { opening = was })

	opening = func(dir string) {
		if err := os.Rename(dir, dir+".was"); err != nil {
			t.Fatal(err)
		}

		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(d.ServeLockFile(), []byte("put there"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	f, err := d.OpenIn(d.ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if b, err := io.ReadAll(f); err != nil || string(b) != "held" {
		t.Errorf("OpenIn(the serve lock), another root put at the name once it held the one there, read %q, %v, want "+
			"the held root's", b, err)
	}
}

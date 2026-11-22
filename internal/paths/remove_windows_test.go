package paths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/privtest"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the folder the walk to it holds,
// following nothing: a junction in it to a folder outside, and one deeper, are removed as junctions,
// and a read-only file is removed with the rest, with what each junction led to untouched, and so is a
// junction at the root's own name. A root whose DACL lets Users add to it, which the readers' check
// refuses, is removed all the same, and the folder it is in is left. A root not there is nothing
// removed. Windows-only, so it runs in CI's platforms job alone.
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

	mklinkJ(t, filepath.Join(root, "anchor"), elsewhere)
	mklinkJ(t, filepath.Join(d.RunDir(), "anchord"), elsewhere)

	readOnly := filepath.Join(root, "conflux.json")
	if err := os.WriteFile(readOnly, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	if err := d.Check(); err == nil {
		t.Fatal("Check(a root Users may add to) = nil, want the readers' refusal this is about")
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

	mklinkJ(t, root, elsewhere)

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s, a junction) = %v, %v, want it removed", root, gone, err)
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
		t.Errorf("RemoveRoot reached %s through a junction: %q, %v", kept, b, err)
	}

	for _, absent := range []string{root, filepath.Join(t.TempDir(), "not", "there")} {
		if gone, err := RemoveRoot(absent); gone || err != nil {
			t.Errorf("RemoveRoot(%s, which is not there) = %v, %v, want nothing removed", absent, gone, err)
		}
	}
}

// TestRemoveRootRemovesWhatGrantsTheAdministratorsNothing: what another account planted in a root,
// owning it under a DACL that grants the Administrators nothing, is removed all the same: a file is
// opened to delete it and read its attributes, which the root's own DACL grants, and not to read it,
// as the access it is opened for says, and a folder, which must be listed, is opened with backup
// intent, which the privileges an Administrator holds grant. Windows-only, so it runs in CI's platforms
// job alone.
func TestRemoveRootRemovesWhatGrantsTheAdministratorsNothing(t *testing.T) {
	inData(t, t.TempDir())

	root := Default().Root
	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	folder := Default().AnchorDir()
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{Default().ConfigFile(), filepath.Join(folder, "inside"), folder} {
		if p != folder {
			if err := os.WriteFile(p, []byte("theirs"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		privtest.SetSecurity(t, p, "D:P(A;;FA;;;SY)")
		privtest.SetOwner(t, p, guests)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(a root holding what grants the Administrators nothing) = %v, %v, want it removed", gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	// Backup intent would grant a read too, so that a file is never opened to be read is what the open
	// asks for, not what it is granted.
	const reads = windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.GENERIC_READ | windows.GENERIC_ALL |
		windows.MAXIMUM_ALLOWED
	if removeAccess&reads != 0 {
		t.Errorf("a file is opened to be removed for %#x, which reads it", removeAccess&reads)
	}
}

// TestRemoveRootJudgesNoFolderAboveIt: nothing above a root is judged before it is removed, as nothing
// is when it is made: a root in a folder whose DACL lets Users delete what is in it is removed.
// Windows-only, so it runs in CI's platforms job alone.
func TestRemoveRootJudgesNoFolderAboveIt(t *testing.T) {
	open := t.TempDir()
	privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

	inData(t, open)

	root := Default().Root
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a root in a folder Users may delete from) = %v, %v, want it removed", gone, err)
	}
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root by a command that has not made it --
// the serve lock tidy asks after -- is opened through the root held (OpenIn), never by its name, and only
// where what is at the root's name is as conflux makes a root (ours): one EnsureAll made is read; a
// junction at the name -- to a folder of this account's own, the folder it is in, or nothing -- is none
// of conflux's, taken as no root at all, nothing in it opened, and so is a folder whose DACL lets Users
// add to it, or that the Guests own. Windows-only, so it runs in CI's platforms job alone.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base := t.TempDir()
	inData(t, base)

	d := Default()
	root := d.Root

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	plant := func(t *testing.T, dir string) {
		if err := os.WriteFile(filepath.Join(dir, "serve.lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ensured := func(t *testing.T) {
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		plant(t, root)
	}

	for _, c := range []struct {
		name string
		make func(t *testing.T)
		ok   bool
	}{
		{"one EnsureAll made", ensured, true},
		{"one Users may add to", func(t *testing.T) {
			ensured(t)
			privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)
		}, false},
		{"one the Guests own", func(t *testing.T) {
			ensured(t)
			privtest.SetOwner(t, root, guests)
		}, false},
		{"a junction to a folder of this account's own", func(t *testing.T) {
			target := t.TempDir()
			plant(t, target)
			mklinkJ(t, root, target)
		}, false},
		{"a junction to the folder it is in", func(t *testing.T) {
			plant(t, base)
			mklinkJ(t, root, base)
		}, false},
		{"a junction to nothing", func(t *testing.T) {
			mklinkJ(t, root, filepath.Join(t.TempDir(), "missing"))
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.make(t)
			t.Cleanup(func() {
				if _, err := RemoveRoot(root); err != nil {
					t.Error(err)
				}
			})

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			switch {
			case c.ok && err != nil:
				t.Errorf("OpenIn(the serve lock), the root %s = %v", c.name, err)
			case !c.ok && !errors.Is(err, fs.ErrNotExist):
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want none of conflux's", c.name, err)
			}
		})
	}
}

// TestOpenInReadsThroughTheRootHeld: what OpenIn opens is looked up in the root it holds, and not by its
// name, so a root put at the name once OpenIn holds the one there -- the one held moved aside, another
// made in its place holding a lock of its own -- answers for nothing: what is read is the held root's.
// Windows-only, so it runs in CI's platforms job alone.
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

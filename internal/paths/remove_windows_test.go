package paths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/privtest"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the folder the walk to it holds,
// following nothing: a junction in it to a folder outside, and one deeper, are removed as junctions,
// and a read-only file is removed with the rest, with what each junction led to untouched, and so is a
// junction at the root's own name. A root whose DACL lets Users add to it, which the readers' check
// refuses, is removed all the same, and the CONFLUX_DIR it is in is left. A root not there is nothing
// removed. Windows-only, so it runs in CI's platforms job alone.
func TestRemoveRootFollowsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", dir)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	root := d.State

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	mklinkJ(t, filepath.Join(root, "anchor"), elsewhere)
	mklinkJ(t, filepath.Join(d.Run, "anchord"), elsewhere)

	readOnly := filepath.Join(root, "conflux.json")
	if err := os.WriteFile(readOnly, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	if err := d.Check(); err == nil {
		t.Fatal("Check(a CONFLUX_DIR Users may add to) = nil, want the readers' refusal this is about")
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	if _, err := os.Lstat(dir); err != nil {
		t.Errorf("RemoveRoot removed the CONFLUX_DIR %s its root was in: %v", dir, err)
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
	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	root := Default().State
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

// TestRemoveRootHoldsACONFLUXDIRsWay: a CONFLUX_DIR's way is held to parents' rule before anything in
// it is removed, as the readers' check holds it, since a way another account may change could lead the
// removal elsewhere: one inside a folder whose DACL lets Users delete what is in it is refused, naming
// that folder, and left. A platform root's way is not judged, as it is not when the root is made, and
// the root is removed. Windows-only, so it runs in CI's platforms job alone.
func TestRemoveRootHoldsACONFLUXDIRsWay(t *testing.T) {
	open := t.TempDir()
	privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

	t.Setenv("CONFLUX_DIR", filepath.Join(open, "conflux"))

	root := Default().State
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("RemoveRoot(a CONFLUX_DIR inside a folder Users may delete from) = %v, %v, want a refusal naming it",
			gone, err)
	}

	if _, err := os.Lstat(root); err != nil {
		t.Errorf("RemoveRoot refusing a CONFLUX_DIR's way removed it: %v", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a platform root inside a folder Users may delete from) = %v, %v, want it removed", gone,
			err)
	}
}

// TestTheWayConfluxMadeIsRemovedWhole: EnsureAll records each folder it made on the way to an
// installation's root, the CONFLUX_DIR among them, and Way reads the record back, deepest first.
// RemoveWay leaves each folder holding a root of conflux's that is there, and once the root is gone
// removes each whole, through handles, whatever it holds; a junction put at a recorded folder's name is
// left, with where it leads untouched. RemoveEmptyWay removes only those that are empty, deepest first.
// Windows-only, so it runs in CI's platforms job alone.
func TestTheWayConfluxMadeIsRemovedWhole(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "a", "b")
	dir := filepath.Join(b, "conflux")

	t.Setenv("CONFLUX_DIR", dir)
	d := Default()
	root := d.State

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	way, err := d.Way()
	if err != nil || !slices.Equal(way, []string{dir, b, a}) {
		t.Fatalf("Way() = %q, %v, want %q", way, err, []string{dir, b, a})
	}

	if removed, err := RemoveWay(way); err != nil || removed != nil {
		t.Errorf("RemoveWay(%q), the root %s there = %q, %v, want nothing removed", way, root, removed, err)
	}

	other := filepath.Join(a, "other")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RemoveRoot(root); err != nil {
		t.Fatal(err)
	}

	elsewhere := t.TempDir()
	junction := mklinkJ(t, filepath.Join(b, "junction"), elsewhere)

	if removed, err := RemoveWay([]string{junction}); err != nil || removed != nil {
		t.Errorf("RemoveWay(a junction at a recorded name) = %q, %v, want nothing removed", removed, err)
	}

	if removed, err := RemoveWay(way); err != nil || !slices.Equal(removed, way) {
		t.Errorf("RemoveWay(%q), %s holding a file and %s a junction = %q, %v, want each removed", way, a, b,
			removed, err)
	}

	if _, err := os.Lstat(a); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemoveWay left %s (Lstat: %v)", a, err)
	}

	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("RemoveWay reached %s: %v", elsewhere, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(a, "kept"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveEmptyWay(way); err != nil || !slices.Equal(removed, []string{dir, b}) {
		t.Errorf("RemoveEmptyWay(%q), %s holding a file = %q, %v, want %q", way, a, removed, err, []string{dir, b})
	}
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root by a command that has not made it --
// the way record uninstall reads, the serve lock tidy asks after -- is opened through the root held
// (OpenIn), never by its name, and only where what is at the root's name is as conflux makes a root
// (ours): one EnsureAll made is read; a junction at the name -- to a folder of this account's own, the
// folder it is in, or nothing -- is none of conflux's, taken as no root at all, nothing in it opened,
// and so is a folder whose DACL lets Users add to it, or that the Guests own, the way record in it among
// what is not read. Windows-only, so it runs in CI's platforms job alone.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base := t.TempDir()
	t.Setenv("CONFLUX_DIR", base)

	d := Default()
	root := d.State

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	plant := func(t *testing.T, dir string) {
		for name, body := range map[string]string{wayName: base + "\n", "serve.lock": ""} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	ensured := func(t *testing.T) {
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		plant(t, root)
	}

	for _, c := range []struct {
		name    string
		make    func(t *testing.T)
		ok, way bool
	}{
		{"one EnsureAll made", ensured, true, true},
		{"one Users may add to", func(t *testing.T) {
			ensured(t)
			privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)
		}, false, false},
		{"one the Guests own", func(t *testing.T) {
			ensured(t)
			privtest.SetOwner(t, root, guests)
		}, false, false},
		{"a junction to a folder of this account's own", func(t *testing.T) {
			target := t.TempDir()
			plant(t, target)
			mklinkJ(t, root, target)
		}, false, false},
		{"a junction to the folder it is in", func(t *testing.T) {
			plant(t, base)
			mklinkJ(t, root, base)
		}, false, false},
		{"a junction to nothing", func(t *testing.T) {
			mklinkJ(t, root, filepath.Join(t.TempDir(), "missing"))
		}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.make(t)
			t.Cleanup(func() {
				if _, err := RemoveRoot(root); err != nil {
					t.Error(err)
				}
			})

			switch way, err := d.Way(); {
			case c.way && (err != nil || !slices.Equal(way, []string{base})):
				t.Errorf("Way(), the root %s = %q, %v, want it read", c.name, way, err)
			case !c.way && (err != nil || way != nil):
				t.Errorf("Way(), the root %s = %q, %v, want no record", c.name, way, err)
			}

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
	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

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
